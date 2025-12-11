
#include <tinycrypt/sha256.h>
// #include <tinycrypt/constants.h>
#include <test_utils.h>

#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_platform_specific.h>
#include <tinycrypt/ecc_dsa.h>
// #include <tinycrypt/ecc_dh.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

char *bin_file = "D:/repos/gitlab/FBL/ais-140/scripts/sign_image/inp/ais_dummy_app_image_2k_signed.bin";

/* Parse binary file and extract data into buffer (block by block)
 * Returns number of bytes read in current block, 0 if EOF, or -1 on error
 * Maintains file position across calls via static FILE pointer */
static int parse_bin_file(const char *filename, uint8_t *data_out, size_t block_size)
{
    static FILE *fp = NULL;
    static int first_call = 1;
    static int eof_reached = 0;

    /* If EOF already reached, return 0 */
    if (eof_reached)
    {
        return 0;
    }

    /* Open file on first call */
    if (first_call)
    {
        fp = fopen(filename, "rb"); /* Open in binary mode */
        if (!fp)
        {
            return -1;
        }
        first_call = 0;
    }

    if (!fp)
    {
        return -1;
    }

    /* Read binary data directly from file */
    size_t bytes_read = fread(data_out, 1, block_size, fp);

    /* Check for read error */
    if (ferror(fp))
    {
        fclose(fp);
        fp = NULL;
        first_call = 1;
        eof_reached = 0;
        return -1;
    }

    /* Check if EOF reached */
    if (feof(fp))
    {
        fclose(fp);
        fp = NULL;
        first_call = 1;
        eof_reached = 1;
    }

    return (int)bytes_read; /* Return bytes read (0 if EOF on next call) */
}

int main(void)
{
    uint8_t block[1024];
    unsigned int result = TC_PASS;
    uint8_t digest[32];
    struct tc_sha256_state_struct s;
    int blk_len;
    int block_num = 0;

    char magic_str[8];
    uint32_t bin_start_address;
    uint32_t bin_size;
    uint32_t bin_execution_start_address;
    uint8_t signature[64]; /* Assuming 64-byte ECDSA signature */

    /*Init sha256 instance*/
    (void)tc_sha256_init(&s);

    /* Read bin file (block by block) and compute hash*/
    while (1)
    {
        /* Parse bin file (adjust filename as needed) */
        blk_len = parse_bin_file(bin_file, block, sizeof(block));
        if (blk_len < 0)
        {
            TC_ERROR("Failed to parse bin file.\n");
            result = TC_FAIL;
            TC_END_RESULT(result);
            return result;
        }
        else if (blk_len > 0 && block_num == 0)
        {
            /*valid block 0*/
            int hash_len = (blk_len < 20) ? blk_len : 20; /* Only first 20 bytes of block 0 are hashed */
            /* Extract meta information from bin */
            if (blk_len >= 20)
            {
                memcpy(magic_str, block + 0, 8);
                bin_start_address = *((uint32_t *)(block + 8));
                bin_size = *((uint32_t *)(block + 12));
                bin_execution_start_address = *((uint32_t *)(block + 16));
                memcpy(signature, block + 20, 64); /* Assuming signature is at the end of block 0 */
                TC_PRINT("Magic: %.8s\n", magic_str);
                TC_PRINT("Start Address: 0x%x\n", bin_start_address);
                TC_PRINT("Size: 0x%x\n", bin_size);
                TC_PRINT("Execution Start: 0x%x\n", bin_execution_start_address);
            }

            /* Hash only first 20 bytes of block 0 */
            tc_sha256_update(&s, block, (size_t)hash_len);
        }
        else if (blk_len > 0 && block_num > 0)
        {
            /*valid block 1 to n*/
            /* Hash remaining blocks completely */
            tc_sha256_update(&s, block, (size_t)blk_len);
        }
        /* EOF reached (blk_len == 0 on second consecutive call) */
        else if (blk_len == 0)
        {
            /*get Computed hash */
            (void)tc_sha256_final(digest, &s);
            break;
        }

        block_num++;
        // TC_PRINT("blk_no %d - %d\n", block_num, blk_len);
    }

    TC_PRINT("SHA256 computation completed over %d blocks.\n", block_num);

    TC_PRINT("Computed SHA256: ");
    for (int i = 0; i < 32; i++)
    {
        TC_PRINT("%02x", digest[i]);
    }
    TC_PRINT("\n");

    /* verify ecdsa signature*/
    int rc;
    const uint8_t pub_bytes[64] = {
        0x09, 0x39, 0x14, 0xe4, 0xe6, 0xea, 0x29, 0xc2,
        0xa0, 0x24, 0x6f, 0xf5, 0x6d, 0x1a, 0xcc, 0xc1,
        0x82, 0xcb, 0x8c, 0xfb, 0xb1, 0x2a, 0x06, 0xde,
        0xd1, 0x7c, 0xe1, 0x50, 0x31, 0xa9, 0x21, 0x82,
        0xdd, 0x69, 0xcf, 0x56, 0x55, 0x80, 0x3a, 0xd1,
        0x2a, 0xf7, 0x81, 0xec, 0x42, 0x0c, 0x3e, 0x83,
        0x7b, 0x4e, 0xc6, 0xf9, 0x25, 0xaa, 0x64, 0x68,
        0x09, 0x52, 0x74, 0x92, 0x56, 0xb6, 0x38, 0xbe};

    rc = uECC_verify(pub_bytes, digest, sizeof(digest), &signature[0],
                     uECC_secp256r1());

    if (rc == TC_CRYPTO_SUCCESS)
    {
        TC_PRINT("ECDSA signature verification SUCCESS.\n");
    }
    else
    {
        TC_PRINT("ECDSA signature verification FAILURE.\n");
        result = TC_FAIL;
    }

    return 0;
}