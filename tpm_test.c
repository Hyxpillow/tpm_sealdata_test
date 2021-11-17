/*******************************************
*                                          *  
* Created by Huang Yuxiang on 2021/11/17   *
* 					   	*
* WHU 2019302120215			   *
*					   *
*******************************************/

#include <stdio.h>
#include <string.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#define BUFFER_LEN 1024

#define DEBUG 1
#define DBG(message,tResult) if(DEBUG) \
{ \
	fprintf(stdout, "(Line %d, %s) %s returned 0x%08x.", __LINE__, __func__, message, tResult); \
	if(tResult) \
		fprintf(stdout, "\033[31m"); \
	else	\
		fprintf(stdout, "\033[32m"); \
	fprintf(stdout, ".%s.\n", Trspi_Error_String(tResult)); \
	fprintf(stdout, "\033[0m"); \
}


int main(int argc, char **argv)
{
	TSS_HCONTEXT hContext=0;
	TSS_HTPM hTPM = 0;
	TSS_RESULT result;
	TSS_HKEY hSRK = 0;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_HPCRS hPCRs;
	TSS_HPOLICY hSRKPolicy;
	UINT32 PCR_output_length = 0;
    BYTE *PCR_output_data;
	BYTE *encrypted_data;
	UINT32 encrypted_data_length;
	
	BYTE input_buffer[BUFFER_LEN] = {0};
	BYTE output_buffer[BUFFER_LEN] = {0};
	UINT32  input_buffer_len = 0;
	
	if (argc != 3) { //需要指定 加密的文件 和 输出文件
		fprintf(stdout, "2 argument needed\n");
		return -1;
	}
	FILE *fp; //把文件字节流读进数组my_buffer
	if ((fp = fopen(argv[1], "rb")) != NULL){
		while(!feof(fp) && input_buffer_len < BUFFER_LEN) {
			fscanf(fp, "%c", &input_buffer[input_buffer_len]);
			input_buffer_len += 1;
		}
		fclose(fp);
		
	} else {
		fprintf(stdout, "fopen failed\n");
		return -2;
	}
	

	result = Tspi_Context_Create(&hContext); 
	//创建上下文对象
	DBG("Create a Context\n", result);
	
	result = Tspi_Context_Connect(hContext, NULL);
	//连接上下文
	DBG("Connect to TPM\n", result);

	result = Tspi_Context_GetTpmObject(hContext, &hTPM); 
	//获得隐式创建的TPM对象的句柄
	DBG("GetTPM handle\n", result);


	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,SRK_UUID, &hSRK); 
	//进行密码认证1
	DBG("Tspi_Context_Connect\n", result);
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
	//进行密码认证2
	DBG("GetPolicy\n", result);
	result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 4, "0540");
	//进行密码认证3
	DBG("SetSecret\n", result);
	

        result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, 0, &hPCRs);
	//创建PCR对象，用于读取PCR寄存器
        DBG("Create PCR object\n", result);

	result = Tspi_TPM_PcrRead(hTPM, 8, &PCR_output_length, &PCR_output_data);
	//读取PCR8中的数据
	DBG("Read the PCR value of PCR 8\n",result);
	result = Tspi_PcrComposite_SetPcrValue(hPCRs, 8, 20, PCR_output_data);
	//将读取到的PCR8中的值写入PCR对象中
	DBG("Set the current value of PCR 8 for sealing\n", result);

	result = Tspi_TPM_PcrRead(hTPM, 9, &PCR_output_length, &PCR_output_data); 
	DBG("Read the PCR value of PCR 9\n",result);
	//读取PCR9中的数据
	result = Tspi_PcrComposite_SetPcrValue(hPCRs, 9, 20, PCR_output_data); 
	DBG("Set the current value of PCR 9 for sealing\n", result);
	//将读取到的PCR9中的值写入PCR对象中
	

	TSS_HOBJECT encrypted_hobject;
	//encrypted_hobject用于存放密文
	result = Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_ENCDATA,TSS_ENCDATA_SEAL,&encrypted_hobject);
	DBG("Create hobject for sealing\n", result);
	
	result = Tspi_Data_Seal(encrypted_hobject, hSRK, input_buffer_len, input_buffer, hPCRs);
	//加密input_buffer
	DBG("Sealing with data object\n", result);

	result = Tspi_GetAttribData(encrypted_hobject, TSS_TSPATTRIB_ENCDATA_BLOB,TSS_TSPATTRIB_ENCDATABLOB_BLOB, \
		&encrypted_data_length, &encrypted_data);
	DBG("Read from encrypted hobject\n", result);
	
	if (encrypted_data_length >= BUFFER_LEN) //如果加密生成的数据大于缓冲区长度，就退出
		return -1;
	
	//把加密结果输出到main第二个参数指定的文件里
	memcpy(output_buffer, encrypted_data, encrypted_data_length);
	if ((fp = fopen(argv[2], "wb")) != NULL){
                fwrite(output_buffer, encrypted_data_length, 1, fp);
		close(fp);
        } else {
                fprintf(stdout, "fopen failed\n");
                return -2;
        }

	Tspi_Context_FreeMemory(hContext, encrypted_data);
	Tspi_Context_CloseObject(hContext, encrypted_hobject);
	Tspi_Context_Close(hContext);
	return 0;
}
