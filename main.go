package main

/*
#cgo LDFLAGS: ./klib/libkaleido.a -ldl
#include "./klib/kaleido.h"
*/
import "C"

//type PoDR2Response struct {
//	data       []byte
//	len        uint
//	cap        uint
//	ref1596880 *C.PoDR2Response
//}
//type sliceHeader struct {
//	Data unsafe.Pointer
//	Len  int
//	Cap  int
//}

func main() {
	C.hello(C.CString("Demo Chiang"))
	//path := C.CString("/root/app.txt")
	//tmp := C.rustdemo(path)
	//output := C.GoString(tmp)
	//
	//fmt.Printf("%s\n", output)
	//defer C.free(unsafe.Pointer(path))
	//ret := C.proof_generate_api(path)
	//resp := NewResponseRef(unsafe.Pointer(ret))
	//fmt.Println("1:", string(resp.data))
	//resp.Deref()
	//fmt.Println("2:", string(resp.data))
	//buf := copyBytes(resp.data, resp.len)
	//fmt.Println("3:", string(buf))
	//defer DestroyPoDR2Response(resp)
}

//func NewResponseRef(ref unsafe.Pointer) *PoDR2Response {
//	if ref == nil {
//		return nil
//	}
//	obj := new(PoDR2Response)
//	obj.ref1596880 = (*C.PoDR2Response)(unsafe.Pointer(ref))
//	return obj
//}
//
//func (x *PoDR2Response) Deref() {
//	if x.ref1596880 == nil {
//		return
//	}
//	stackPtr := (*sliceHeader)(unsafe.Pointer(&x.data))
//	stackPtr.Data = unsafe.Pointer(x.ref1596880.vec_ptr)
//	stackPtr.Cap = (int)(x.ref1596880.cap)
//	stackPtr.Len = (int)(x.ref1596880.len)
//
//	x.len = (uint)(x.ref1596880.len)
//}
//
//func copyBytes(v []byte, vLen uint) []byte {
//	buf := make([]byte, vLen)
//	if n := copy(buf, v[:vLen]); n != int(vLen) {
//		panic("partial read")
//	}
//
//	return buf
//}
//
//// DestroyPoDR2Response release memory
//func DestroyPoDR2Response(ptr *PoDR2Response) {
//	C.destroy_PoDR2_response(ptr.ref1596880)
//}
