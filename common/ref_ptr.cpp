#include <map>

#include "ref_ptr.h"
#include "Assert.h"

//#define USE_MUTEX
//#define USE_FUNCTION_STATS

#if defined(USE_MUTEX)
#include <wx/thread.h>
#endif

#if defined(USE_FUNCTION_STATS)
#include "FunctionStats.h"
#endif

using namespace std;

typedef map<void *, int> ReferenceCountMap;
static ReferenceCountMap ref_counts;
#if defined(USE_MUTEX)
static wxMutex mutex;
#endif

void RefCounter::incRef(void *heap_object)
{
#if defined(USE_FUNCTION_STATS)
    FunctionStats func("RefCounter::incRef");
#endif

    if (heap_object == 0)
        return;

#if defined(USE_MUTEX)
    wxMutexLocker lock(mutex);
#endif

    ref_counts[heap_object]++;
}

bool RefCounter::decRef(void *heap_object)
{
#if defined(USE_FUNCTION_STATS)
    FunctionStats func("RefCounter::decRef");
#endif

    ASSERT(heap_object != 0);

#if defined(USE_MUTEX)
    wxMutexLocker lock(mutex);
#endif

    int n = --ref_counts[heap_object];

    return n == 0;
}

int RefCounter::getRef(void *heap_object)
{
#if defined(USE_FUNCTION_STATS)
    FunctionStats func("RefCounter::getRef");
#endif

    ASSERT(heap_object != 0);

#if defined(USE_MUTEX)
    wxMutexLocker lock(mutex);
#endif

    return ref_counts[heap_object];
}
