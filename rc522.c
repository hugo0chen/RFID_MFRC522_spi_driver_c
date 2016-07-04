#include "rc522.h"
#include "string.h"
//#include "usart_1.h"
#include "delay.h"

#define MAXRLEN 18    
/**********************�˿ڶ���********************************
				MF522_RST     =    PB10;                   
				SDA/MF522_CS  =    PB12 ; 
				MF522_SCK     =    PB13;
				MF522_MOSI    =    PB15;
				MF522_MISO    =    PB14;
*************************************************************/

#define MF522_RST_Clr() GPIO_ResetBits(RC522_GPIO_define.pin_of_rst_group,RC522_GPIO_define.pin_of_rst)
#define MF522_RST_Set() GPIO_SetBits(RC522_GPIO_define.pin_of_rst_group,RC522_GPIO_define.pin_of_rst)

#define MF522_CS_Clr() GPIO_ResetBits(RC522_GPIO_define.pin_of_cs_group,RC522_GPIO_define.pin_of_cs)
#define MF522_CS_Set() GPIO_SetBits(RC522_GPIO_define.pin_of_cs_group,RC522_GPIO_define.pin_of_cs)

#define MF522_SCK_Clr() GPIO_ResetBits(RC522_GPIO_define.pin_of_sck_group,RC522_GPIO_define.pin_of_sck)
#define MF522_SCK_Set() GPIO_SetBits(RC522_GPIO_define.pin_of_sck_group,RC522_GPIO_define.pin_of_sck)

#define MF522_MOSI_Clr()  GPIO_ResetBits(RC522_GPIO_define.pin_of_mosi_group,RC522_GPIO_define.pin_of_mosi)
#define MF522_MOSI_Set() GPIO_SetBits(RC522_GPIO_define.pin_of_mosi_group,RC522_GPIO_define.pin_of_mosi)

#define MF522_MISO_Get() GPIO_ReadInputDataBit(RC522_GPIO_define.pin_of_miso_group,RC522_GPIO_define.pin_of_miso)

uint8_t MLastSelectedSnr[4];
uint8_t DefaultKey[6];

struct RC522_defines{
	GPIO_TypeDef* pin_of_rst_group;
	uint16_t pin_of_rst;
	GPIO_TypeDef* pin_of_cs_group;
	uint16_t pin_of_cs;
	GPIO_TypeDef* pin_of_sck_group;
	uint16_t pin_of_sck;
	GPIO_TypeDef* pin_of_mosi_group;
	uint16_t pin_of_mosi;
	GPIO_TypeDef* pin_of_miso_group;
	uint16_t pin_of_miso;
};

struct RC522_defines RC522_GPIO_define = {GPIOB,GPIO_Pin_10,GPIOB,GPIO_Pin_12,GPIOB,GPIO_Pin_13,GPIOB,GPIO_Pin_15,GPIOB,GPIO_Pin_14};
/*************************************************************
  Function   :RC522_GPIO_Init  
  Description:��ʼ�� RC522 ��IO����
  Input      : ��Ӧ�Ķ˿ڽṹ������        
  return     : none    
*************************************************************/
static void RC522_GPIO_Init(struct RC522_defines def)
{
	GPIO_InitTypeDef GPIO_InitStructure;
	
	RCC_AHBPeriphClockCmd(RCC_AHBPeriph_GPIOB,ENABLE);

	GPIO_InitStructure.GPIO_Pin = def.pin_of_rst;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_OUT;          //GPIO_Mode_Out_PP
	GPIO_InitStructure.GPIO_OType = GPIO_OType_PP;
   GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_UP;
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_2MHz;
	GPIO_Init(def.pin_of_rst_group, &GPIO_InitStructure);
	MF522_RST_Set();
	
	GPIO_InitStructure.GPIO_Pin = def.pin_of_cs;           //cs output mode
	GPIO_Init(def.pin_of_cs_group, &GPIO_InitStructure);
	MF522_CS_Set();
	
	GPIO_InitStructure.GPIO_Pin = def.pin_of_sck;					//sck output mode
	GPIO_Init(def.pin_of_sck_group, &GPIO_InitStructure);
	MF522_SCK_Set();
	
	GPIO_InitStructure.GPIO_Pin = def.pin_of_mosi;        //mosi output mode
	GPIO_Init(def.pin_of_mosi_group, &GPIO_InitStructure);
	MF522_MOSI_Set();
		
	GPIO_InitStructure.GPIO_Pin = def.pin_of_miso;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN; 				 //input mode MISO  
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_2MHz;
	GPIO_Init(def.pin_of_miso_group, &GPIO_InitStructure);
}

/*************************************************************
  Function   :RC522_Init  
  Description:��ʼ�� RC522 
  Input      : none   
  return     : none    
*************************************************************/
void RC522_Init(void)
{
	RC522_GPIO_Init(RC522_GPIO_define);
	PcdReset();					// ��λ
	PcdAntennaOn();
}
/*************************************************************
  Function   ��PcdRequest
  Discription: Ѱ��
	Input      :
							req_code[IN]:Ѱ����ʽ
                0x52 = Ѱ��Ӧ�������з���14443A��׼�Ŀ�
                0x26 = Ѱδ��������״̬�Ŀ�
							pTagType[OUT]����Ƭ���ʹ���
                0x4400 = Mifare_UltraLight
                0x0400 = Mifare_One(S50)
                0x0200 = Mifare_One(S70)
                0x0800 = Mifare_Pro(X)
                0x4403 = Mifare_DESFire
  Return     : �ɹ�����MI_OK
*************************************************************/
uint8_t PcdRequest(uint8_t req_code,uint8_t *pTagType)
{
   uint8_t status;  
   uint16_t  unLen;
   uint8_t ucComMF522Buf[MAXRLEN]; 

   ClearBitMask(Status2Reg,0x08);
   WriteRawRC(BitFramingReg,0x07);
   SetBitMask(TxControlReg,0x03);
   ucComMF522Buf[0] = req_code;
   status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,1,ucComMF522Buf,&unLen);

   if ((status == MI_OK) && (unLen == 0x10))
   {    
       *pTagType     = ucComMF522Buf[0];
       *(pTagType+1) = ucComMF522Buf[1];
   }
   else
   {   
			status = MI_ERR;   
	 }
   
   return status;
}
/*************************************************************
  Function   ������ײ
  Discription: 
	Input			 : pSnr[OUT]:��Ƭ���кţ�4�ֽ�
  Return     : �ɹ�����MI_OK
*************************************************************/  
uint8_t PcdAnticoll(uint8_t *pSnr)
{
    uint8_t status;
    uint8_t i,snr_check=0;
    uint16_t  unLen;
    uint8_t ucComMF522Buf[MAXRLEN]; 

    ClearBitMask(Status2Reg,0x08);
    WriteRawRC(BitFramingReg,0x00);
    ClearBitMask(CollReg,0x80);
 
    ucComMF522Buf[0] = PICC_ANTICOLL1;
    ucComMF522Buf[1] = 0x20;

    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,2,ucComMF522Buf,&unLen);

    if (status == MI_OK)
    {
    	 for (i=0; i<4; i++)
         {   
             *(pSnr+i)  = ucComMF522Buf[i];
             snr_check ^= ucComMF522Buf[i];
         }
         if (snr_check != ucComMF522Buf[i])
         {   
						status = MI_ERR;    
				 }
    }
    
    SetBitMask(CollReg,0x80);
    return status;
}

/*************************************************************
  Function   ��ѡ����Ƭ
  Discription: 
	Input      :pSnr[IN]:��Ƭ���кţ�4�ֽ�
  Return     : �ɹ�����MI_OK
*************************************************************/
uint8_t PcdSelect(uint8_t *pSnr)
{
    uint8_t status;
    uint8_t i;
    uint16_t  unLen;
    uint8_t ucComMF522Buf[MAXRLEN]; 
    
    ucComMF522Buf[0] = PICC_ANTICOLL1;
    ucComMF522Buf[1] = 0x70;
    ucComMF522Buf[6] = 0;
    for (i=0; i<4; i++)
    {
    	ucComMF522Buf[i+2] = *(pSnr+i);
    	ucComMF522Buf[6]  ^= *(pSnr+i);
    }
    CalulateCRC(ucComMF522Buf,7,&ucComMF522Buf[7]);
  
    ClearBitMask(Status2Reg,0x08);

    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,9,ucComMF522Buf,&unLen);
    
    if ((status == MI_OK) && (unLen == 0x18))
    {   status = MI_OK;  }
    else
    {   status = MI_ERR;    }

    return status;
}

/*************************************************************
  Function   ����֤��Ƭ����
  Discription: 
	Input      :
							auth_mode[IN]: ������֤ģʽ
                 0x60 = ��֤A��Կ
                 0x61 = ��֤B��Կ 
							addr[IN]�����ַ
							pKey[IN]������
							pSnr[IN]����Ƭ���кţ�4�ֽ�
  Return     : �ɹ�����MI_OK
*************************************************************/               
uint8_t PcdAuthState(uint8_t auth_mode,uint8_t addr,uint8_t *pKey,uint8_t *pSnr)
{
    uint8_t status;
    uint16_t  unLen;
    uint8_t i,ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = auth_mode;
    ucComMF522Buf[1] = addr;
    for (i=0; i<6; i++)
    {    
			ucComMF522Buf[i+2] = *(pKey+i);   
		}
    for (i=0; i<6; i++)
    {    
			ucComMF522Buf[i+8] = *(pSnr+i);   
		}
    
    status = PcdComMF522(PCD_AUTHENT,ucComMF522Buf,12,ucComMF522Buf,&unLen);
    if ((status != MI_OK) || (!(ReadRawRC(Status2Reg) & 0x08)))
    {   
			status = MI_ERR;   
		}
    
    return status;
}

/*************************************************************
  Function   ��PcdRead
  Discription: ��ȡM1��һ������
	Input      :
							addr[IN]�����ַ
              pData[OUT]�����������ݣ�16�ֽ�
  Return     : �ɹ�����MI_OK
*************************************************************/ 
uint8_t PcdRead(uint8_t addr,uint8_t *pData)
{
    uint8_t status;
    uint16_t  unLen;
    uint8_t i,ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = PICC_READ;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
   
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);
		printf("PcdComMF522 %d \n\r",status);
    if ((status == MI_OK) && (unLen == 0x90))
    {
        for (i=0; i<16; i++)
        {    
					*(pData+i) = ucComMF522Buf[i];   
				}
    }
    else
    {   
			status = MI_ERR;   
		}
    
    return status;
}
/*************************************************************
  Function	 ��PcdWrite
  Discription: д���ݵ�M1��һ��
	Input      :  
							addr[IN]�����ַ
              pData[IN]��д������ݣ�16�ֽ�
  Return		 : �ɹ�����MI_OK
*************************************************************/                  
uint8_t PcdWrite(uint8_t addr,uint8_t *pData)
{
    uint8_t status;
    uint16_t  unLen;
    uint8_t i,ucComMF522Buf[MAXRLEN]; 
    
    ucComMF522Buf[0] = PICC_WRITE;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {   status = MI_ERR;   }
        
    if (status == MI_OK)
    {
        for (i=0; i<16; i++)
        {    
					ucComMF522Buf[i] = *(pData+i);   
				}
        CalulateCRC(ucComMF522Buf,16,&ucComMF522Buf[16]);

        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,18,ucComMF522Buf,&unLen);
        if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
        {
					status = MI_ERR;   
				}
    }
    
    return status;
}
/*************************************************************
  Function   ��PcdHalt
  Discription:���Ƭ��������״̬
	Input			 : none
	Return     : �ɹ�����MI_OK
*************************************************************/
uint8_t PcdHalt(void)
{
    uint8_t status;
    uint16_t  unLen;
    uint8_t ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = PICC_HALT;
    ucComMF522Buf[1] = 0;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);
		
    return status;
}

/*************************************************************
	Function   ��CalulateCRC
	Discription: ��MF522����CRC16����
	Input			 : *pIndata ---������CRCԴ����
							 len ---���ݳ���
							 *pOutData  ---����õ��Ĵ���CRC������
	Return     : none
*************************************************************/
void CalulateCRC(uint8_t *pIndata,uint8_t len,uint8_t *pOutData)
{
    uint8_t i,n;
    ClearBitMask(DivIrqReg,0x04);
    WriteRawRC(CommandReg,PCD_IDLE);
    SetBitMask(FIFOLevelReg,0x80);
    for (i=0; i<len; i++)
    {   
			WriteRawRC(FIFODataReg, *(pIndata+i));   
		}
    WriteRawRC(CommandReg, PCD_CALCCRC);
    i = 0xFF;
    do 
    {
        n = ReadRawRC(DivIrqReg);
        i--;
    }
    while ((i!=0) && !(n&0x04));
    pOutData[0] = ReadRawRC(CRCResultRegL);
    pOutData[1] = ReadRawRC(CRCResultRegM);
}

/*************************************************************
	Function   ��PcdReset
	Discription: ��λRC522
	Input			 : none
	Return     : �ɹ�����MI_OK  
*************************************************************/
uint8_t PcdReset(void)
{
		__ASM("NOP");
    MF522_RST_Set();
    delay_us(1);
    MF522_RST_Clr();
    delay_us(1);
    MF522_RST_Set();
    delay_us(1);
    WriteRawRC(CommandReg,PCD_RESETPHASE);
    delay_us(1);
    
    WriteRawRC(ModeReg,0x3D);            //��Mifare��ͨѶ��CRC��ʼֵ0x6363
    WriteRawRC(TReloadRegL,30);           
    WriteRawRC(TReloadRegH,0);
    WriteRawRC(TModeReg,0x8D);
    WriteRawRC(TPrescalerReg,0x3E);
    WriteRawRC(TxAutoReg,0x40);     
    return MI_OK;
}
/*************************************************************
	Function   ��M500PcdConfigISOType
	Discription: ����ISO����
	Input			 : none
	Return     : �ɹ�����MI_OK  
*************************************************************/
uint8_t M500PcdConfigISOType(uint8_t type)
{
   if (type == 'A')                     //ISO14443_A
   { 
       ClearBitMask(Status2Reg,0x08);
       WriteRawRC(ModeReg,0x3D);
       WriteRawRC(RxSelReg,0x86);
       WriteRawRC(RFCfgReg,0x7F);   
   	   WriteRawRC(TReloadRegL,30);  		// TReloadVal = 'h6a =tmoLength(dec) 
	     WriteRawRC(TReloadRegH,0);
       WriteRawRC(TModeReg,0x8D);
	     WriteRawRC(TPrescalerReg,0x3E);
	   
	     delay_ms(10);
       PcdAntennaOn();
   }
   else
	 {
		 return MI_NOTAGERR; 
	 }
   
   return MI_OK;
}
/*************************************************************
	Function   ��M500PcdConfigISOType
	Discription: 
	Input			 : Address[IN]:�Ĵ�����ַ
	Return     ��������ֵ
*************************************************************/
uint8_t ReadRawRC(uint8_t Address)
{
     uint8_t i, ucAddr;
     uint8_t ucResult=0;

     MF522_SCK_Clr();
     MF522_CS_Clr();
     ucAddr = ((Address<<1)&0x7E)|0x80;
		//write register address 
     for(i=8;i>0;i--)
     {
         if(ucAddr&0x80)
					MF522_MOSI_Set();
				else
					MF522_MOSI_Clr();
         MF522_SCK_Set();
         ucAddr <<= 1;
         MF522_SCK_Clr();
     }
		// read data
     for(i=8;i>0;i--)
     {
         MF522_SCK_Set();
         ucResult <<= 1;
         ucResult|=MF522_MISO_Get();
         MF522_SCK_Clr();
     }

     MF522_CS_Set();
     MF522_SCK_Set();
     return ucResult;
}
/*************************************************************
  Function   :WriteRawRC
  Description:���ַΪaddress�ļĴ���д������value
  Input      : address ---  Ҫд�����ݵļĴ�����ַ
							 value   ---  Ҫд�������
  return     : none    
*************************************************************/
void WriteRawRC(uint8_t Address, uint8_t value)
{  
    uint8_t  i, ucAddr; 

    MF522_CS_Clr();
    MF522_SCK_Clr();
    ucAddr = ((Address<<1)&0x7E) ;
	// write register address
    for(i=8;i>0;i--)
		{
			 if(ucAddr&0x80)
        MF522_MOSI_Set();
      else
        MF522_MOSI_Clr(); 
      MF522_SCK_Set();
      ucAddr <<= 1;
      MF522_SCK_Clr();
		}
		//write data
    for(i=8;i>0;i--)
		{
			if(value&0x80)
        MF522_MOSI_Set();
      else
        MF522_MOSI_Clr();
      MF522_SCK_Set();
      value <<= 1;
      MF522_SCK_Clr();
		}
	
    MF522_SCK_Clr();
    MF522_CS_Set();
}

/*************************************************************
  Function    :SetBitMask
  Description:����RC522�Ĵ���λ
  Input       : reg  --- reg:�Ĵ�����ַ
							  mask --- ��λֵ
  return      : none     
*************************************************************/
void SetBitMask(uint8_t reg,uint8_t mask)  
{
    uint8_t tmp = 0x0;
    tmp = ReadRawRC(reg);
    WriteRawRC(reg,tmp | mask);  // set bit mask
}
/*************************************************************
  Function    : SetBitMask
  Description:����RC522�Ĵ���λ
  Input       : reg  --- reg:�Ĵ�����ַ
							  mask --- ��λֵ
  return      : none
*************************************************************/
void ClearBitMask(uint8_t reg,uint8_t mask)  
{
    uint8_t tmp = 0x0;
    tmp = ReadRawRC(reg);
    WriteRawRC(reg, tmp & ~mask);  // clear bit mask
} 

/*************************************************************
  Function   ��PcdComMF522
	Discription:ͨ��RC522��ISO14443��ͨѶ
  Input      :Command[IN]:RC522������
              pInData[IN]:ͨ��RC522���͵���Ƭ������
              InLenByte[IN]:�������ݵ��ֽڳ���
              pOutData[OUT]:���յ��Ŀ�Ƭ��������
              *pOutLenBit[OUT]:�������ݵ�λ����
	Return		 :�ɹ�����MI_OK  
*************************************************************/
uint8_t PcdComMF522(uint8_t Command,uint8_t *pInData,uint8_t InLenByte,uint8_t *pOutData, uint16_t  *pOutLenBit)
{
    uint8_t status = MI_ERR;
    uint8_t irqEn   = 0x00;
    uint8_t waitFor = 0x00;
    uint8_t lastBits;
    uint8_t n;
    uint16_t i;
    switch (Command)
    {
       case PCD_AUTHENT:
          irqEn   = 0x12;
          waitFor = 0x10;
          break;
       case PCD_TRANSCEIVE:
          irqEn   = 0x77;
          waitFor = 0x30;
          break;
       default:
         break;
    }
   
    WriteRawRC(ComIEnReg,irqEn|0x80);
    ClearBitMask(ComIrqReg,0x80);
    WriteRawRC(CommandReg,PCD_IDLE);
    SetBitMask(FIFOLevelReg,0x80);
    
    for (i=0; i<InLenByte; i++)
    {   WriteRawRC(FIFODataReg, pInData[i]);    }
    WriteRawRC(CommandReg, Command);
   
    
    if (Command == PCD_TRANSCEIVE)
    {    SetBitMask(BitFramingReg,0x80);  }
    
   //����ʱ��Ƶ�ʵ���������M1�����ȴ�ʱ��25ms
    i = 2000;
    do 
    {
         n = ReadRawRC(ComIrqReg);
         i--;
    }
    while ((i!=0) && !(n&0x01) && !(n&waitFor));
    ClearBitMask(BitFramingReg,0x80);
	      
    if (i!=0)
    {    
         if(!(ReadRawRC(ErrorReg)&0x1B))
         {
             status = MI_OK;
             if (n & irqEn & 0x01)
             {   
								status = MI_NOTAGERR;   
						 }
             if (Command == PCD_TRANSCEIVE)
             {
               	n = ReadRawRC(FIFOLevelReg);
              	lastBits = ReadRawRC(ControlReg) & 0x07;
                if (lastBits)
                {
									*pOutLenBit = (n-1)*8 + lastBits;   
								}
                else
                {
									*pOutLenBit = n*8;   
								}
                if (n == 0)
                { 
									n = 1;    
								}
                if (n > MAXRLEN)
                {
									n = MAXRLEN;   
								}
                for (i=0; i<n; i++)
                {
									pOutData[i] = ReadRawRC(FIFODataReg);    
								}
            }
         }
         else
         {
						status = MI_ERR;   
				 }        
   }
 
   SetBitMask(ControlReg,0x80);           // stop timer now
   WriteRawRC(CommandReg,PCD_IDLE); 
   return status;
}
/*************************************************************
  Function   ��PcdAntennaOn
	Discription:��������  
							ÿ��������ر����շ���֮��Ӧ������1ms�ļ��
  Input      : none
	Return		 : none
*************************************************************/
void PcdAntennaOn()
{
    uint8_t i;

	  WriteRawRC(TxAutoReg,0x40);
  delay_ms(10);
  i = ReadRawRC(TxControlReg);
  if(!(i&0x03))
    SetBitMask(TxControlReg, 0x03);
  i=ReadRawRC(TxAutoReg);   
}


/*************************************************************
  Function   ��PcdAntennaOff
	Discription:�ر�����  
  Input      : none
	Return		 : none
*************************************************************/
void PcdAntennaOff()
{
    ClearBitMask(TxControlReg, 0x03);
}
/*************************************************************
	Function   :PcdValue
  Discription: �ۿ�ͳ�ֵ
	Input      :dd_mode[IN]��������
               0xC0 = �ۿ�
               0xC1 = ��ֵ
						addr[IN]  ��Ǯ����ַ
						pValue[IN]��4�ֽ���(��)ֵ����λ��ǰ
  Return: �ɹ�����MI_OK
*************************************************************/                 
uint8_t PcdValue(uint8_t dd_mode,uint8_t addr,uint8_t *pValue)
{
    uint8_t status;
    uint16_t  unLen;
    uint8_t ucComMF522Buf[MAXRLEN]; 
    
    ucComMF522Buf[0] = dd_mode;
    ucComMF522Buf[1] = addr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {   
			status = MI_ERR;   
		}
        
    if (status == MI_OK)
    {
        memcpy(ucComMF522Buf, pValue, 4);
        CalulateCRC(ucComMF522Buf,4,&ucComMF522Buf[4]);
        unLen = 0;
        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,6,ucComMF522Buf,&unLen);
        if (status != MI_ERR)
        {
					status = MI_OK;    
				}
    }
    
    if (status == MI_OK)
    {
        ucComMF522Buf[0] = PICC_TRANSFER;
        ucComMF522Buf[1] = addr;
        CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]); 
   
        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

        if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
        {   
					status = MI_ERR;   
				}
    }
    return status;
}

/*************************************************************
  Function	 :PcdBakValue
  Discription: ����Ǯ��
	Input			 :sourceaddr[IN]��Դ��ַ
							goaladdr[IN]��Ŀ���ַ
  Return     : �ɹ�����MI_OK
*************************************************************/
uint8_t PcdBakValue(uint8_t sourceaddr, uint8_t goaladdr)
{
    uint8_t status;
    uint16_t  unLen;
    uint8_t ucComMF522Buf[MAXRLEN]; 

    ucComMF522Buf[0] = PICC_RESTORE;
    ucComMF522Buf[1] = sourceaddr;
    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {   
			status = MI_ERR;   
		}
    
    if (status == MI_OK)
    {
        ucComMF522Buf[0] = 0;
        ucComMF522Buf[1] = 0;
        ucComMF522Buf[2] = 0;
        ucComMF522Buf[3] = 0;
        CalulateCRC(ucComMF522Buf,4,&ucComMF522Buf[4]);
 
        status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,6,ucComMF522Buf,&unLen);
        if (status != MI_ERR)
        {
					status = MI_OK;    
				}
    }
    
    if (status != MI_OK)
    {   
			return MI_ERR;   
		}
    
    ucComMF522Buf[0] = PICC_TRANSFER;
    ucComMF522Buf[1] = goaladdr;

    CalulateCRC(ucComMF522Buf,2,&ucComMF522Buf[2]);
 
    status = PcdComMF522(PCD_TRANSCEIVE,ucComMF522Buf,4,ucComMF522Buf,&unLen);

    if ((status != MI_OK) || (unLen != 4) || ((ucComMF522Buf[0] & 0x0F) != 0x0A))
    {
			status = MI_ERR;   
		}

    return status;
}
/*************************************************************
  Function	 :iccardcode
  Discription: �Կ�Ƭ������Ӧ�Ĳ���
							halt find collision read write parameters-setting
	Input			 :none
  Return     :none
*************************************************************/
void iccardcode(uint8_t *Buffer)
{	     
  uint8_t cmd;
	uint8_t status;
	
	cmd = Buffer[0];
	switch(cmd)
 	{
		case 1:    // Halt the card  
			status= PcdHalt();;			
			Buffer[0]=1;
			Buffer[1]=status;
			break;			
		case 2:   // Request,Anticoll,Select,return CardType(2 bytes)+CardSerialNo(4 bytes)
			        // Ѱ��������ͻ��ѡ��    ���ؿ����ͣ�2 bytes��+ ��ϵ�к�(4 bytes)
			status= PcdRequest(Buffer[1],&Buffer[2]);
			if(status!=0)
			{
				status= PcdRequest(Buffer[1],&Buffer[2]);
				if(status!=0)				
				{
					Buffer[0]=1;	
					Buffer[1]=status;
					break;
				}
			}  
			Buffer[0]=3;	
			Buffer[1]=status;
			break;
		case 3:     // ����ͻ ������ϵ�к� MLastSelectedSnr
			status = PcdAnticoll(&Buffer[2]);
			if(status!=0)
			{
				Buffer[0]=1;	
				Buffer[1]=status;
				break;
			}
			memcpy(MLastSelectedSnr,&Buffer[2],4);
			Buffer[0]=5;
			Buffer[1]=status;
			break;	
		case 4:		 // ѡ�� Select Card
			status=PcdSelect(MLastSelectedSnr);
			if(status!=MI_OK)
			{
				Buffer[0]=1;	
				Buffer[1]=status;
				break;
			}
			Buffer[0]=3;
			Buffer[1]=status;
			break;
		case 5:	    // Key loading into the MF RC500's EEPROM
      status = PcdAuthState(Buffer[1], Buffer[3], DefaultKey, MLastSelectedSnr);// У�鿨����
			Buffer[0]=1;
			Buffer[1]=status;	
			break;							
		case 6: 
			Buffer[0]=1;
			Buffer[1]=status;			
			break;				
		case 7:     
    		Buffer[0]=1;
			Buffer[1]=status;			
			break;
		case 8:     // Read the mifare card
			status=PcdRead(Buffer[1],&Buffer[2]);
			if(status==0)
			{Buffer[0]=17;}
			else
			{Buffer[0]=1;}
			Buffer[1]=status;	
			break;
		case 9:     // Write the mifare card
			status=PcdWrite(Buffer[1],&Buffer[2]);
			Buffer[0]=1;
			Buffer[1]=status;			
			//usart1_sendbyte(Buffer,18);
			break;
		case 10:
       PcdValue(Buffer[1],Buffer[2],&Buffer[3]);
			Buffer[0]=1;	
			Buffer[1]=status;
			break;
		case 12:    // ��������
		  PcdBakValue(Buffer[1], Buffer[2]);
			Buffer[0]=1;	//contact
			Buffer[1]=0;
			break;		
	}
}

/*************************************************************
  Function	 :Find_Card
  Discription: Ѱ�� ����ӡ��Ӧ�Ŀ�Ƭ������
	Input			 :none
  Return     :none
*************************************************************/
void Find_Card(void)
{
		uint8_t Temp[2];
    if(PcdRequest(0x52,Temp)==MI_OK)
    {
      if(Temp[0]==0x04&&Temp[1]==0x00)  
          printf("MFOne-S50");
      else if(Temp[0]==0x02&&Temp[1]==0x00)
          printf("MFOne-S70");
      else if(Temp[0]==0x44&&Temp[1]==0x00)
          printf("MF-UltraLight");
      else if(Temp[0]==0x08&&Temp[1]==0x00)
          printf("MF-Pro");
      else if(Temp[0]==0x44&&Temp[1]==0x03)
          printf("MF Desire");
      else
         printf("Unknown");
      printf(" SUCCESS!\n\r");
    }
    else
		{			
			printf("Find Failed! \n\r");                                             
		}
}




