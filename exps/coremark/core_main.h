/*
 * core_main.h
 *
 *  Created on: Jul 17, 2023
 *      Author: itemqq
 */

#ifndef CORE_MAIN_H_
#define CORE_MAIN_H_

#include "coremark.h"

#if MAIN_HAS_NOARGC
MAIN_RETURN_TYPE core_main(void);
#else
MAIN_RETURN_TYPE core_main(int argc, char *argv[]);
#endif

#endif /* CORE_MAIN_H_ */
