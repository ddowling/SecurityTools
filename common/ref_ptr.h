// Yet another implementation of a C++ refptr class. This all should be part
// of STL. I wanted a refptr implementation that did not pose any restrictions
// of the classes that are reference counted and one that is also threadsafe
//
#ifndef OSSCORE_REFPTR
#define OSSCORE_REFPTR
//
// Class to wrap all of the reference counts to all object in a thread safe and
// portable manner
class RefCounter
{
public:
    static void incRef(void *heap_object);
    // Return true if the reference count goes to zero
    static bool decRef(void *heap_object);
    static int getRef(void *head_object);
};

template<class X> class ref_ptr
{
public:
    ref_ptr(X* p=0)
        : ptr(p)
        {
	    RefCounter::incRef(ptr);
	}

    ref_ptr(const ref_ptr& r)
        : ptr(r.ptr)
        {
		RefCounter::incRef(ptr);
	}

    template<class T> ref_ptr(ref_ptr<T>& r)
        : ptr(r.ptr)
        {
	    RefCounter::incRef(ptr);
	}

    ~ref_ptr()
        {
	    if (ptr != 0 && RefCounter::decRef(ptr))
	        delete ptr;
	}

    ref_ptr& operator=(const ref_ptr& r)
        {
	    if (ptr != 0 && RefCounter::decRef(ptr))
		delete ptr;

            ptr = r.ptr;
            RefCounter::incRef(ptr);

	    return *this;
	}

    void set(X *p)
	{
	    if (ptr != 0 && RefCounter::decRef(ptr))
		delete ptr;

            ptr = p;
            RefCounter::incRef(ptr);
	}

    operator X*() const
        {
	    return ptr;
	}

    X* getRaw() const
	{
	    return ptr;
	}

    X* operator->() const
        {
	    return ptr;
	}

    bool isNull() const
	{
	    return ptr == 0;
	}

    bool isNotNull() const
	{
	    return ptr != 0;
	}

    // ref_ptrs are equal if what they point to to the same thing
    bool operator==(const ref_ptr &p) const
        {
	    return ptr == p.ptr;
	}
    bool operator!=(const ref_ptr &p) const
        {
	    return ptr != p.ptr;
	}

protected:
    X *ptr;
};

#endif
