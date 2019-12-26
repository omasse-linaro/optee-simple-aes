/*
 * Copyright (c) 2019, NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <simple_aes_ta.h>

int main(void)
{
	TEEC_Context ctx;
	TEEC_Session sess;

	char key[32];
	char iv[16];
	char clear[4096];
	char cipher[4096];

	TEEC_UUID uuid = TA_SIMPLE_AES_UUID;
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
	{
		printf("TEE initialize failed 0x%08X\n",res);
		goto err;
	}

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
	{
		printf("open session failed 0x%08X\n",res);
		goto err;
	}

	memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	memset(iv, 0, sizeof(iv)); /* set iv to NULL */

	memset(clear, 0x5a, sizeof(clear)); /* Load some dummy value */

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = sizeof(key);
	op.params[1].tmpref.buffer = iv;
	op.params[1].tmpref.size = sizeof(iv);
	op.params[2].tmpref.buffer = clear;
	op.params[2].tmpref.size = sizeof(clear);
	op.params[3].tmpref.buffer = cipher;
	op.params[3].tmpref.size = sizeof(cipher);

	res = TEEC_InvokeCommand(&sess, 0,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
	{
		printf("invoke failed 0x%08X origin %d\n",res,origin);
		goto err;
	}

	printf("SUCCESS\n");

err:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
