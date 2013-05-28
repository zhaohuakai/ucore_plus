/*-----------------------------------------------------------------------
/  Low level disk interface modlue include file
/-----------------------------------------------------------------------*/  
    
#include <kio.h>
#include <fs.h>
#include <ide.h>
#include <inode.h>
#include "fatfs/diskio.h"
    
#define PRINTFSINFO 1
    
/*---------------------------------------*/ 
/* Prototypes for disk control functions */ 

{
	
#if PRINTFSINFO
	    FAT_PRINTF("[FATFS], assign %d to %d\n", st, ed);
	
#endif /* 
	    return 1;



{
	
#if PRINTFSINFO
	    FAT_PRINTF("[FATFS], disk_init on drive%d\n", drive);
	
#endif /* 
	    return 0;



{
	
	    //FAT_PRINTF("[FATFS], disk_status on drive%d\n", drive);
	    return 0;



		     BYTE sectorCount)
{
	
	    //FAT_PRINTF("[FATFS], disk_read on drive%d\n", drive);
	    //from dev_diso0.c read_blks
	int ret;
	
//  kprintf("disk_read ## %d\n", drive);
	    if ((ret =
		 ide_read_secs(MMC0_DEV_NO, sectorNumber, buffer,
			       sectorCount)) != 0) {
		
		    ("fat: read blkno = %d (sectno = %d), nblks = %d (nsecs = %d): 0x%08x.\n",
		     
	
	



#if	_READONLY == 0
    DRESULT disk_write(BYTE drive, const BYTE * buffer, DWORD sectorNumber,
		       BYTE sectorCount)
{
	
	    //FAT_PRINTF("[FATFS], disk_write on drive%d\n", drive);
	int ret;
	
	      ide_write_secs(MMC0_DEV_NO, sectorNumber, buffer,
			     sectorCount)) != 0) {
		
		    ("fat: write blkno = %d (sectno = %d), nblks = %d (nsecs = %d): 0x%08x.\n",
		     
	
	



#endif /* 
    DRESULT disk_ioctl(BYTE drive, BYTE command, void *buffer)
{
	
	    //FAT_PRINTF("[FATFS], disk_ioctl on drive%d, command = %d\n", drive, command);
	    return 0;


