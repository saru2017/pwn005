#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void saru()
{
  char buf[128];

  gets(buf);
  puts(buf);
}

int main(){
  saru();

  return 0;
}

