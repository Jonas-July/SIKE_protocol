#include <stdio.h>
#include <string.h>

#include "P751_api.h"
#include "Comm_node.h"

int main()
{

	printf("Creating Nodes...\n");
	struct Comm_node USB_KEY = create_Comm_node();
	printf("Done creating USB_KEY\n");
	struct Comm_node CPU = create_Comm_node();
	printf("Done creating CPU\n");

	printf("\n");

	set_other_public_key(&CPU, USB_KEY.pk_own);
	set_other_public_key(&USB_KEY, CPU.pk_own);

	int diff_pk = memcmp(CPU.pk_other, USB_KEY.pk_own, CRYPTO_PUBLICKEYBYTES);
	printf(diff_pk == 0 ? "Public key of CPU correct\n" : "Public key wrong\n");
	

	printf(	memcmp(USB_KEY.pk_other, CPU.pk_own, CRYPTO_PUBLICKEYBYTES) == 0 
		? "Public key of USB_KEY correct\n" 
		: "Public key wrong\n");

	printf("\n");

	/*************************
		Start of protocol
	*/
	printf("-----------------\nStart of protocol\n-----------------\n\n");


	printf("Generating shared secret USB->CPU...\n");
	unsigned char* ct_UC = generate_shared_secret(&USB_KEY);

	//send ct_UC to CPU
	printf("Sending to CPU...\n");

	decrypt_shared_secret(&CPU, ct_UC);

	printf("Communication successful!\n");
	printf( memcmp(CPU.ss_channel_from, USB_KEY.ss_channel_to, CRYPTO_BYTES) == 0 
		? "Transmission correct.\n" 
		: "Transmission wrong.\n");

	printf("\n");

        printf("Generating shared secret CPU->USB...\n");
	unsigned char* ct_CU = generate_shared_secret(&CPU);

        //send ct_CU to USB
        printf("Sending to USB...\n");

	decrypt_shared_secret(&USB_KEY, ct_CU);

        printf("Communication successful!\n");
	printf( memcmp(USB_KEY.ss_channel_from, CPU.ss_channel_to, CRYPTO_BYTES) == 0 
		? "Transmission correct.\n" 
		: "Transmission wrong.\n");


	printf("\n");

	printf("Generating ephemeral key pairs...\n");
	generate_ephemeral_keypair(&USB_KEY);
	printf("Done generating keypair of USB_KEY\n");
	generate_ephemeral_keypair(&CPU);	
	printf("Done generating keypair of CPU\n");

	printf("\n");

	printf("Encrypting ephemeral public key of USB_KEY\n");
	unsigned char* enc_pk_eph_usb = encrypt_ephemeral(&USB_KEY);

	printf("Sending encrypted ephemeral public key of USB_KEY...\n");
	decrypt_ephemeral(&CPU, enc_pk_eph_usb);
	printf("Communication successful!\n");

	printf( memcmp(CPU.pk_eph_other, USB_KEY.pk_eph, CRYPTO_PUBLICKEYBYTES) == 0
		? "Transmission correct.\n"
		: "Transmission wrong.\n");

	printf("\n");

        printf("Encrypting ephemeral public key of CPU\n");
        unsigned char* enc_pk_eph_cpu = encrypt_ephemeral(&CPU);

        printf("Sending encrypted ephemeral public key of CPU...\n");
        decrypt_ephemeral(&USB_KEY, enc_pk_eph_cpu);
        printf("Communication successful!\n");

        printf( memcmp(USB_KEY.pk_eph_other, CPU.pk_eph, CRYPTO_PUBLICKEYBYTES) == 0
                ? "Transmission correct.\n"
                : "Transmission wrong.\n");

	printf("\n");
	
	/*
		Exchange of symmetric session keys
	*/
        printf("Generating shared secret USB->CPU...\n");
        unsigned char* ct_UC_session = generate_shared_session_secret(&USB_KEY);

        //send ct_UC to CPU
        printf("Sending to CPU...\n");

        decrypt_shared_session_secret(&CPU, ct_UC_session);

        printf("Communication successful!\n");
        printf( memcmp(CPU.ss_channel_from_session, USB_KEY.ss_channel_to_session, CRYPTO_BYTES) == 0
                ? "Transmission correct.\n"
                : "Transmission wrong.\n");

        printf("\n");

        printf("Generating shared secret CPU->USB...\n");
        unsigned char* ct_CU_session = generate_shared_secret(&CPU);

        //send ct_CU to USB
        printf("Sending to USB...\n");

        decrypt_shared_secret(&USB_KEY, ct_CU_session);

        printf("Communication successful!\n");
        printf( memcmp(USB_KEY.ss_channel_from_session, CPU.ss_channel_to_session, CRYPTO_BYTES) == 0
                ? "Transmission correct.\n"
                : "Transmission wrong.\n");


        printf("\n");

	/**********************
		End of protocol
	*/
	printf("---------------\nEnd of protocol\n---------------\n\n");

	printf("Protocol done. Symmetric keys are now secure\n");

	delete_Comm_node(&CPU);
	delete_Comm_node(&USB_KEY);

	return 0;
}
