#ifndef __ISA_ARGPARSE_HPP__
#define __ISA_ARGPARSE_HPP__

bool argparse_collector(programArguments p, collector* clt);

bool argparse_isHelpActive(programArguments p);

bool argparse_checkNumericalValues(programArguments p, uint* activeTimer, uint* inactiveTimer, uint* flowCacheSize);

void argparse_printReport(programArguments p, collector* clt, uint activeTimer, uint inactiveTimer, uint flowCacheSize);

void argparse_setFile(programArguments p, data* programData);

#endif