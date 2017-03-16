# flashext_pykd
WinDBG PYKD Python Extension for Flash Debugging - FlashExt

## How to show help information?
```
0:000> !py -g flashext.py --help
usage: WinDBG PYKD Python Extension - FlashExt [-h] [--tjit] [--bpjit BPJIT]
                                               [--lnjit LNJIT]
                                               [--export_embedded]

optional arguments:
  -h, --help         show this help message and exit
  --tjit             trace JIT functions
  --bpjit BPJIT      set breakpoint on JIT functions by name
  --lnjit LNJIT      displays JIT symbols at or near given address
  --export_embedded  export embedded content
``

## How to trace JIT function?
```
0:000> !py -g flashext.py --tjit
Trace JIT Functions ...
Method Address: 0x54e4f70, Method Name: Function$/createEmptyFunction
Method Address: 0x54e4d71, Method Name: Object$/_dontEnumPrototype
Method Address: 0x54e48cd, Method Name: Object$/_init
Method Address: 0x54f4ed5, Method Name: flash.geom::Rectangle
Method Address: 0x54f4e4b, Method Name: flash.display::Stage
Method Address: 0x54f4db4, Method Name: flash.display::DisplayObjectContainer
Method Address: 0x54f4d24, Method Name: flash.display::InteractiveObjectVector.<flash.display::Stage3D>
Method Address: 0x54f4c9d, Method Name: flash.display::DisplayObject
Method Address: 0x54f4bea, Method Name: flash.events::EventDispatcher
Method Address: 0x5504d1c, Method Name: ViuTopHotelImageg
Method Address: 0x54f4b5d, Method Name: flash.display::MovieClip_
Method Address: 0x54f4a98, Method Name: flash.display::Sprite
Method Address: 0x550447d, Method Name: GBdsfwefwfw$/dgfhr5t34fedf
Method Address: 0x54e4796, Method Name: String/http://adobe.com/AS3/2006/builtin::replace
Method Address: 0x55041a4, Method Name: ViuTopHotelImage/uyyuffgsdthytjyth
Method Address: 0x5504019, Method Name: Vbdhergsasddf$/cvfbegrfwedsf
Method Address: 0x5503f79, Method Name: DleepButtonFiles_bin$60f1e6ca873222d8bf6013ec57357d2b131176204
Method Address: 0x54e46bc, Method Name: flash.utils::ByteArray
Method Address: 0x55039c8, Method Name: GBdsfwefwfw$/bgrthgerfe
Method Address: 0x54f4a13, Method Name: flash.display::LoaderInfo
Method Address: 0x54f4971, Method Name: flash.display::Loader
Method Address: 0x54f4710, Method Name: flash.display::Loader/loadBytes
Method Address: 0x54f457d, Method Name: flash.display::Loader/_buildLoaderContext
Method Address: 0x54f4331, Method Name: flash.system::LoaderContext
Method Address: 0x54f426b, Method Name: flash.system::ApplicationDomain
Method Address: 0x54f419f, Method Name: flash.display::Stage/addChild
Method Address: 0x54f3fd5, Method Name: flash.events::Event
Method Address: 0x551462b, Method Name: class_7
Method Address: 0x55136b2, Method Name: class_7/method_19
Method Address: 0x54f3c8d, Method Name: flash.display::LoaderInfo/get parameters
Method Address: 0x551307a, Method Name: class_7/method_50
Method Address: 0x5512934, Method Name: class_7/method_35
Method Address: 0x551218b, Method Name: class_7/method_56
Method Address: 0x54e4335, Method Name: String/http://adobe.com/AS3/2006/builtin::split
Method Address: 0x54e3e79, Method Name: Array
Method Address: 0x5524f15, Method Name: _a_-_---$/_a_--_--
Method Address: 0x552486f, Method Name: _a_-_---$/_a_-_--
Method Address: 0x55247cc, Method Name: _a_-_-___a_-_--
Method Address: 0x552473a, Method Name: mx.core::ByteArrayAsset
Method Address: 0x55246b3, Method Name: _a_-_
Method Address: 0x5524611, Method Name: _a_---
Method Address: 0x5524333, Method Name: _a_-_---$/_a_-__-_
Method Address: 0x55240d4, Method Name: _a_-_---$/_a_--__
Method Address: 0x5523f77, Method Name: _a_-_-_
Method Address: 0x55237e1, Method Name: _a_-_-_/_a_-
Method Address: 0x5523742, Method Name: _a_-_-_/_a_---_
Method Address: 0x5523570, Method Name: _a_-_-_/_a_-_--_
Method Address: 0x55231b7, Method Name: _a_-_-_/_a_-__-
```

## How to set breakpoint at JIT function?
```
0:000> .load pykd
0:000> !py -g flashext.py --bpjit "flash.display::Loader/loadBytes"
set breakpoint at "flash.display::Loader/loadBytes"
Cannot find addr_flash_base in globals, try to analyze flash module info...
search signature of getmethodname ...
Address of MethodInfo__getMethodName is: 0x6e866870
search signature of setjit ...
Address of SetJIT is: 0x6e889d70
search signature of unused memory ...
Address of Unused Memory is: 0x6e8e308c
(a14.560): Break instruction exception - code 80000003 (first chance)
0:019> g
Try to modify SetJIT function to call getMethodName
offset hex format is: 0x5930b
[0x51, 0x56, 0x90, 0xe9, 0xb, 0x93, 0x5, 0x0]
offset hex format is: -0x7c823
[0x89, 0xf1, 0xe8, 0xdd, 0x37, 0xf8, 0xff, 0x5e, 0x59, 0x8b, 0x46, 0x30, 0x25, 0xff, 0xff, 0x7f, 0xff, 0xe9, 0x0, 0x0, 0x0, 0x0]
offset hex format is: -0x59321
[0x89, 0xf1, 0xe8, 0xdd, 0x37, 0xf8, 0xff, 0x5e, 0x59, 0x8b, 0x46, 0x30, 0x25, 0xff, 0xff, 0x7f, 0xff, 0xe9, 0xdf, 0x6c, 0xfa, 0xff]
set breakpoint at addr_unused_memory+0x09 for getting method name
Method Address: 0x52e4f57, Method Name: Function$/createEmptyFunction
Method Address: 0x52e4d5a, Method Name: Object$/_dontEnumPrototype
Method Address: 0x52e48b0, Method Name: Object$/_init
Method Address: 0x52f4ee9, Method Name: flash.geom::Rectangle
Method Address: 0x52f4e45, Method Name: flash.display::Stage
Method Address: 0x52f4db3, Method Name: flash.display::DisplayObjectContainer
Method Address: 0x52f4d23, Method Name: flash.display::InteractiveObjectVector.<flash.display::Stage3D>
Method Address: 0x52f4c84, Method Name: flash.display::DisplayObject
Method Address: 0x52f4bcd, Method Name: flash.events::EventDispatcher
Method Address: 0x5304d22, Method Name: ViuTopHotelImageg
Method Address: 0x52f4b44, Method Name: flash.display::MovieClip_
Method Address: 0x52f4a84, Method Name: flash.display::Sprite
Method Address: 0x5304474, Method Name: GBdsfwefwfw$/dgfhr5t34fedf
Method Address: 0x52e4777, Method Name: String/http://adobe.com/AS3/2006/builtin::replace
Method Address: 0x5304181, Method Name: ViuTopHotelImage/uyyuffgsdthytjyth
Method Address: 0x5303ff7, Method Name: Vbdhergsasddf$/cvfbegrfwedsf
Method Address: 0x5303f63, Method Name: DleepButtonFiles_bin$60f1e6ca873222d8bf6013ec57357d2b131176204
Method Address: 0x52e46a1, Method Name: flash.utils::ByteArray
Method Address: 0x53039b8, Method Name: GBdsfwefwfw$/bgrthgerfe
Method Address: 0x52f49ef, Method Name: flash.display::LoaderInfo
Method Address: 0x52f495c, Method Name: flash.display::Loader
Method Address: 0x52f46e4, Method Name: flash.display::Loader/loadBytes
>>> flash.display::Loader/loadBytes
eax=0455ddd8 ebx=02dfc160 ecx=00000001 edx=052f46e4 esi=00000017 edi=046db020
eip=052f46e4 esp=02dfc114 ebp=02dfc134 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00200206
052f46e4 55              push    ebp
```

## How to find near symbol by address?
```
0:005> !py -g flashext.py --lnjit 0x5304181
list near symbol at: 0x5304181
Find exact matched symbol: ViuTopHotelImage/uyyuffgsdthytjyth
0:005> !py -g flashext.py --lnjit 0x5304170
list near symbol at: 0x5304170
Find near symbol:
Vbdhergsasddf$/cvfbegrfwedsf (0x5303ff7) | ViuTopHotelImage/uyyuffgsdthytjyth (0x5304181)
```