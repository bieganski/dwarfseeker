# Example

```cpp
// test.cc

class MyClass {

public:
int value;

    __attribute__ ((noinline))
    MyClass(int value) : value(value * 0x123) {}

    __attribute__ ((always_inline))
    MyClass(unsigned int value) : value((int) value * 0x345) {}
};

int main(int argc, char** argv) {
    auto instance1 = MyClass(argc);
    auto instance2 = MyClass((unsigned int) argc);
    return 0 ;
}

```

```bash
g++ -g3 test.cc
```

```bash
m.bieganski@hostname:~$ ./dwarfseeker.py  -d a.out  | c++filt
ENTRY_TYPE,FILE_START_OFFSET,FILE_END_OFFSET,SYMBOL_NAME,COMPILATION_UNIT_PATH
REGULAR_FUNCTION,0x1149,0x11aa,main,home/m.bieganski/test.cc
INLINE_EXPANSION,0x1182,0x118f,MyClass::MyClass(unsigned int),home/m.bieganski/test.cc
OUT_OF_LINE,0x11aa,0x11cb,MyClass::MyClass(int),home/m.bieganski/test.cc
```

```bash
m.bieganski@hostname:~$ objdump -d  ./a.out | c++filt
...
0000000000001149 <main>:
    1149:	f3 0f 1e fa          	endbr64 
    114d:	55                   	push   %rbp
...
00000000000011aa <MyClass::MyClass(int)>:
    11aa:	f3 0f 1e fa          	endbr64
    11ae:	55                   	push   %rbp
...
    1182:	8b 45 f4             	mov    -0xc(%rbp),%eax
    1185:	69 c0 45 03 00 00    	imul   $0x345,%eax,%eax     // note inline expansion
    118b:	89 45 f0             	mov    %eax,-0x10(%rbp)
    118e:	90                   	nop
    118f:	b8 00 00 00 00       	mov    $0x0,%eax
    1194:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
...
```

# Distribution

* MIT license
* a single Python script
* `pyelftools` is the only external dependency (see [requirements.txt](./requirements.txt))
* works for any architecture that is supported by `pyelftools`. For non-x86, usually there is a limitation, that the input ELF shall not have relocations (ET_EXEC should always work)