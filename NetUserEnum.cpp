/*	################ BORRADOR
	
	Author   : tty503
	GitHub   : github.com/tty503
	Twitter  : twitter.com/tty_503
	Telegram : t.me/tty503

	#################
		Prueba de la utilización de NetUserEnum para la enumeración de cuentas locales. 
*/

// Para WinXP
#define _WIN32_WINNT 0x0501

// Programa basado en caracteres Unicode 
#ifndef UNICODE
#define UNICODE
#endif


#include <stdio.h>
	//	Proporciona el núcleo de las capacidades de entrada/salida del lenguaje C.

#include <assert.h>
	//	Contiene la macro assert (aserción), utilizada para detectar errores lógicos 
	//		y otros tipos de fallos en la depuración de un programa.  

#include <windows.h>
	//	Contiene las declaraciones de todas las funciones de la biblioteca Windows API,
	//		todas las macros utilizadas por los programadores de aplicaciones para Windows, 
	//		y todas las estructuras de datos utilizadas en gran cantidad de funciones y subsistemas.

#include <lmaccess.h>
	//	Contiene a la función "NetUserEnum" que permite recupera información sobre todas las cuentas 
	//		de usuario de un servidor.

#include <lmapibuf.h>
	//	Contiene a la función "NetApiBufferFree" que permite liberar la memoria (asignada por NetApiBufferAllocate),
	//		Las aplicaciones también deben llamar a NetApiBufferFree para liberar la memoria que otras funciones 
	//		de gestión de red utilizan internamente para devolver información.
	//
	//	En este caso en particular, por NetUserEnum. 

#include <lmerr.h>
	//	Códigos de error para ADSI.

#pragma comment(lib, "netapi32.lib")

//	Este programa acepta 1 argumento, un nombre de servidor
//		si no, se asume el ordenador local.
int wmain(int argc, wchar_t *argv[ ])
{
	// Utilice el tipo LPUSER_INFO_1 para obtener más información de nivel 1.
	LPUSER_INFO_1 pBuf = NULL;
	LPUSER_INFO_1 pTmpBuf;
	
	DWORD dwLevel = 1;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;	
	DWORD i;
	DWORD dwTotalCount = 0;
	
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;
	
	// Si argc == 1, se asume el ordenador local
	if(argc > 2)
	{
		fwprintf(stderr, L"Se utiliza: %s [ServerName]\n", argv[0]);
		exit(1);
	}
	
	// El nombre del servidor se suministra para que no sea el ordenador local por defecto.
	if(argc == 2)
	{
		pszServerName = argv[1];
	}

	wprintf(L"\nCuentas de usuario, banderas y sus privilegios en maquina: %s \n", pszServerName);
	
	//	Llama a la función NetUserEnum(), especificando el nivel 0,
	//		enumerar sólo los tipos de cuentas de usuario globales.
	do
	{ 	// comenzar a hacer
		
		//	Si pszServerName es NULL, se asume que es la PC local, aquí usamos servername pero
		//		es sólo una máquina local de WinXP.  
		//	También otras entradas como la contraseña, etc.
		nStatus = NetUserEnum(pszServerName,
								dwLevel,
								FILTER_NORMAL_ACCOUNT, // Usuarios globales, modifícalo de forma adecuada 
													  //	para excavar otra información
								(LPBYTE*)&pBuf,
								dwPrefMaxLen,
								&dwEntriesRead,
								&dwTotalEntries,
								&dwResumeHandle);

		// Si la llamada tiene éxito,
		if((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if((pTmpBuf = pBuf) != NULL)
			{
				// Recorre las entradas en bucle.
				for(i = 0; (i < dwEntriesRead); i++)
				{
					// Comprobar el búfer
					assert(pTmpBuf != NULL);
					
					if(pTmpBuf == NULL)
					{
						fprintf(stderr, "Se ha producido una violación de acceso\n");
						break;
					}

					// Imprime el nombre de la cuenta de usuario, la bandera y su privilegio.
					wprintf(L"... %s::%0x::%0x\n", pTmpBuf->usri1_name, pTmpBuf->usri1_flags, pTmpBuf->usri1_priv);
					pTmpBuf++;
					dwTotalCount++;
				}
			}
		}
		// En caso contrario, imprime el error del sistema.
		else
		{
			fprintf(stderr, "Se ha producido un error en el sistema: %d\n", nStatus);
		}

		// Liberar el búfer asignado.
		if(pBuf != NULL)
		{
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	}// Continúa llamando a NetUserEnum mientras haya más entradas.
	while (nStatus == ERROR_MORE_DATA); // fin de hacer

	// Compruebe de nuevo la memoria asignada.
	if(pBuf != NULL)
	{
		NetApiBufferFree(pBuf);
	}
	
	// Imprime el recuento final de usuarios enumerados.
	fprintf(stderr, "\nTotal de %d entradas enumeradas\n", dwTotalCount);

	return 0;
}