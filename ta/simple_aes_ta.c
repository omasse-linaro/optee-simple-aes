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

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <simple_aes_ta.h>

TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	/* Nothing to do */
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
				      uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle trans_key;
	TEE_Attribute attrs;
	TEE_OperationHandle op_encrypt;
	TEE_OperationHandle op_decrypt;

	uint8_t *keybuffer;
	uint8_t *iv;
	uint32_t iv_len;
	uint8_t *srcdata, *destdata;
	uint32_t srclen, destlen;
	uint8_t *plaindata;
	uint32_t plainlen;

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	keybuffer = params[0].memref.buffer;
	iv = params[1].memref.buffer;
	iv_len = params[1].memref.size;
	srcdata = params[2].memref.buffer;
	srclen = params[2].memref.size;
	destdata = params[3].memref.buffer;
	destlen = params[3].memref.size;

	/* need a 256bits key size */
	if (params[0].memref.size != 32)
		return TEE_ERROR_BAD_PARAMETERS;

	plaindata = TEE_Malloc(plainlen);
	if (!plaindata)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* allocate the cipher operations */

	res = TEE_AllocateOperation(&op_encrypt,
				    TEE_ALG_AES_CTR /* choose algo here */,
				    TEE_MODE_ENCRYPT,
				    256 /* key size in bits */);
	if (res != TEE_SUCCESS) {
		EMSG("can not allocate operation (0x%x)", res);
		goto out;
	}

	res = TEE_AllocateOperation(&op_decrypt,
				    TEE_ALG_AES_CTR /* choose algo here */,
				    TEE_MODE_DECRYPT,
				    256 /* key size in bits */);
	if (res != TEE_SUCCESS) {
		EMSG("can not allocate operation (0x%x)", res);
		goto out;
	}

	/* allocate the aes key + init attributes */

	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
					  256,
					  &trans_key);
	if (res != TEE_SUCCESS) {
		EMSG("can not allocate transient object 0x%x", res);
		goto out1;
	}

	TEE_RestrictObjectUsage(trans_key, TEE_USAGE_EXTRACTABLE | TEE_USAGE_ENCRYPT | TEE_USAGE_DECRYPT,);

	TEE_InitRefAttribute(&attrs,
			     TEE_ATTR_SECRET_VALUE,
			     keybuffer,
			     32 /* key size in byte */);

	res = TEE_PopulateTransientObject(trans_key, &attrs, 1);
	if (res != TEE_SUCCESS) {
		EMSG("populate transient object error");
		goto out2;
	}

	/* program cipher operation key */

	res = TEE_SetOperationKey(op_encrypt, trans_key);
	if (res != TEE_SUCCESS) {
		EMSG("can not set operation key");
		goto out2;
	}
	res = TEE_SetOperationKey(op_decrypt, trans_key);
	if (res != TEE_SUCCESS) {
		EMSG("can not set operation key");
		goto out2;
	}

	/* encrypt srcdata in destdata */
	TEE_CipherInit(op_encrypt, iv, ivlen);
	res = TEE_CipherDoFinal(op_encrypt, srcdata, srclen, destdata, destlen);
	if (res != TEE_SUCCESS) {
		EMSG("can not do AES %x", res);
		goto out2;
	}

	/* decrypt destdata in plaindata */
	TEE_CipherInit(op_decrypt, iv, ivlen);
	res = TEE_CipherDoFinal(op_decrypt, destdata, destlen, plaindata, plainlen);
	if (res != TEE_SUCCESS) {
		EMSG("can not do AES %x", res);
		goto out2;
	}

	/* verify that plaindata == srcdata */
	if (plainlen != srclen) {
		EMSG("AES operation failed");
		res = TEE_ERROR_GENERIC;
		goto out2;
	}
	if (memcmp(plaindata, srcdata, srclen)) {
		EMSG("AES operation failed");
		res = TEE_ERROR_GENERIC;
	}

out2:
	TEE_FreeTransientObject(trans_key);
out1:
	TEE_FreeOperation(op_encrypt);
	TEE_FreeOperation(op_decrypt);
out:
	return res;
}

