#include <stdint.h>
#include <stdio.h>
#include <climits>
#include "tins/tins.h"
// #include "tins/utils/resolve_utils.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    try
    {
        Tins::Utils::resolve_domain(str);
    }
    catch (Tins::exception_base e)
    {
    }

    return 0;
}
