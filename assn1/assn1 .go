package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type Filemetadata struct {
	Identifier uuid.UUID

	Enkey []byte

	Hashkey []byte
	Iv      []byte
}

type User struct {
	Username []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
	Password []byte

	Pkey userlib.PrivateKey

	Owned  map[string]Filemetadata
	Shared map[string]Filemetadata
}

//Filemetadata hb

//Maccheck jh
type Maccheck struct {
	Realdata []byte
	Checkmac []byte
}

//Inode hb
type Inode struct {
	Size       int
	Fileid     uuid.UUID
	Doublepntr [32][32]string
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	if (len(data) % configBlockSize) != 0 {
		return errors.New("File size not valid")
	}
	uuidfile := uuid.New()
	fileenckeyc := userlib.RandomBytes(userlib.AESKeySize)
	filemackeyc := userlib.RandomBytes(userlib.AESKeySize)
	// jsndata, err := json.Marshal(data)
	// fmt.Println(jsndata, "\njsndata")
	// if err != nil {
	// 	return err
	// }
	iv := make([]byte, userlib.BlockSize)
	completedata := make([]byte, len(iv)+configBlockSize)
	iv = completedata[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	//fmt.Println("iv used  ", iv)
	iv123 := make([]byte, userlib.BlockSize)

	length := len(data) / configBlockSize
	//fmt.Println(length, "                                         ", len(completedata)%configBlockSize)
	var tempdpntr [32][32]string
	h := 0
	j := -1
	path := ""
	for i := 0; i < length; i++ {
		if i%32 == 0 {
			j++
			h = 0
		}
		//fmt.Println(i, "   ", j, "    ", h)
		encrypt := userlib.CFBEncrypter(fileenckeyc, iv)
		//fmt.Println(len(data), "         ", data)
		encrypt.XORKeyStream(completedata[userlib.BlockSize:], data[(i*configBlockSize):((i+1)*configBlockSize)])
		//fmt.Println("xorkeystream       ", encrypt)
		//fmt.Println(len(completedata), "             ", completedata)
		//fmt.Println("length of new data from where it starts", len(completedata)-userlib.BlockSize)
		copy(iv123, completedata[(len(completedata)-userlib.BlockSize):])
		//fmt.Println("nahi jaunga      ", completedata[(len(completedata)-userlib.BlockSize):], "     ", iv123)
		//fmt.Println(iv, "                   ", len(iv))
		tempdpntr[j][h] = bytesToUUID(userlib.RandomBytes(16)).String()
		path = "files" + "/" + tempdpntr[j][h]
		//println(path)
		//fmt.Println("length of complete data", len(completedata))
		datafilenode123, err := json.Marshal(completedata)
		//fmt.Println("run       ", datafilenode123)
		//fmt.Println("length of data                  ", len(datafilenode123))
		copy(iv, iv123)
		if err != nil {
			return err
		}
		//fmt.Println(datatosend)
		emacdatatosend := []byte((string)(datafilenode123) + tempdpntr[j][h])
		//fmt.Println(emacdatatosend)
		if err != nil {
			return err
		}
		emac := userlib.NewHMAC(filemackeyc)
		emac.Write(emacdatatosend)
		//fmt.Println(path)
		mkg := emac.Sum(nil)
		cdata := Maccheck{datafilenode123, mkg}
		marshalcdata, err := json.Marshal(cdata)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(path, marshalcdata)
		h++

	}
	filemeta := Filemetadata{uuidfile, fileenckeyc, filemackeyc, iv123}
	//fmt.Println("iv123      ", iv123)
	userdata.Owned[filename] = filemeta

	var inodefile Inode
	uuidfileinode := uuid.New()
	inodefile = Inode{length, uuidfileinode, tempdpntr}
	jsndatafilenode, err := json.Marshal(&inodefile)
	if err != nil {
		return err
	}
	ivfilenode := make([]byte, userlib.BlockSize)
	datafilenode := make([]byte, len(ivfilenode)+len(jsndatafilenode))
	ivfilenode = datafilenode[:userlib.BlockSize]

	copy(ivfilenode, completedata[:userlib.BlockSize])

	encryptfilenode := userlib.CFBEncrypter(fileenckeyc, ivfilenode)
	encryptfilenode.XORKeyStream(datafilenode[userlib.BlockSize:], jsndatafilenode)
	emac12 := userlib.NewHMAC(filemackeyc)
	emac12.Write(datafilenode)
	mn := emac12.Sum(nil)
	cdata5, err := json.Marshal(Maccheck{datafilenode, mn})
	if err != nil {
		return err
	}
	userlib.DatastoreSet("working/"+uuidfile.String(), cdata5)
	err = Datastoresenddata(*userdata)
	if err != nil {
		return err
	}
	//send encrypted data to datastore
	return err
}

// AppendFile should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//fmt.Println("\n\n\n\n\n Appendfile")
	var isCreated, isShared bool
	var file Filemetadata
	file, isCreated = userdata.Owned[filename]
	if !isCreated {
		file, isShared = userdata.Shared[filename]
		if !isShared {
			return errors.New("Filename invalid or access not permitted")
		}
	}

	if (len(data) % configBlockSize) != 0 {
		return errors.New("length not valid")
	}

	enckey := file.Enkey
	Hashkey := file.Hashkey
	identifier := file.Identifier
	iv := file.Iv
	//	fmt.Println("                                        ", file.Iv)
	//	fmt.Println("iv usd iv     ", iv, " mine   ", enckey)
	var inodefile Inode

	//change file data node information
	fileinodeinfomarshal, received := userlib.DatastoreGet("working/" + identifier.String())
	if received == false {
		return errors.New("cant fetch data")
	}

	var cdata Maccheck
	err = json.Unmarshal(fileinodeinfomarshal, &cdata)
	if err != nil {
		return err
	}

	emac := userlib.NewHMAC(Hashkey)
	emac.Write(cdata.Realdata)
	hemac := emac.Sum(nil)

	checkok := userlib.Equal(hemac, cdata.Checkmac)
	if checkok == false {
		return errors.New("data is corrupted")
	}
	//decryt
	completedata1 := make([]byte, len(cdata.Realdata[userlib.BlockSize:]))
	ivinode := cdata.Realdata[:userlib.BlockSize]
	decrypt := userlib.CFBDecrypter(enckey, ivinode)
	decrypt.XORKeyStream(completedata1, cdata.Realdata[userlib.BlockSize:])
	err = json.Unmarshal(completedata1, &inodefile)
	if err != nil {
		return errors.New("cannot unmarshal data")
	}

	//encrypt fileinode

	//encryption
	length := len(data) / configBlockSize
	lngthofdata := inodefile.Size
	//	fmt.Println("size of data", length)
	inodefile.Size = length + inodefile.Size
	//	fmt.Println("length size       ", inodefile.Size)
	//encryption
	// encrypt := userlib.CFBEncrypter(enckey, iv)
	// fmt.Println("encryption ", encrypt)
	// completedata := make([]byte, length*configBlockSize)
	// encrypt.XORKeyStream(completedata, data)
	// iv = completedata[(len(completedata) - userlib.BlockSize):]
	iv123 := make([]byte, userlib.BlockSize)

	ivfile := make([]byte, userlib.BlockSize)
	completedata := make([]byte, len(iv)+configBlockSize)
	ivfile = completedata[:userlib.BlockSize]
	copy(ivfile, iv)
	//MAC KEY
	h := lngthofdata % 32
	j := lngthofdata / 32
	path := ""
	//	fmt.Println("lngthofdata    ", lngthofdata)
	//	fmt.Println("                   ", h, "                  ", j)
	//	fmt.Println("length              ", length)
	for i := lngthofdata; i < inodefile.Size; i++ {
		if i%32 == 0 {
			j++
			h = 0
		}
		//	fmt.Println(i, "   ", j, "    ", h)
		encrypt := userlib.CFBEncrypter(enckey, iv)
		//	fmt.Println(len(data), "         ", data)
		encrypt.XORKeyStream(completedata[userlib.BlockSize:], data[((i-lngthofdata)*configBlockSize):(((i+1)-lngthofdata)*configBlockSize)])
		//	fmt.Println("xorkeystream       ", encrypt)
		//	fmt.Println(len(completedata), "             ", completedata)
		//	fmt.Println("length of new data from where it starts", len(completedata)-userlib.BlockSize)
		copy(iv123, completedata[(len(completedata)-userlib.BlockSize):])
		copy(iv, iv123)
		//	fmt.Println(iv, "                   ", len(iv))
		inodefile.Doublepntr[j][h] = bytesToUUID(userlib.RandomBytes(16)).String()
		path = "files" + "/" + inodefile.Doublepntr[j][h]
		//println(path)
		//	fmt.Println("length of complete data", len(completedata))
		datafilenode123, err := json.Marshal(completedata)
		//	fmt.Println("run       ", datafilenode123)
		//	fmt.Println("length of data                  ", len(datafilenode123))
		if err != nil {
			return err
		}
		//fmt.Println(datatosend)
		emacdatatosend := []byte((string)(datafilenode123) + inodefile.Doublepntr[j][h])
		//	fmt.Println(emacdatatosend)
		if err != nil {
			return err
		}
		emac := userlib.NewHMAC(Hashkey)
		emac.Write(emacdatatosend)
		//	fmt.Println(path)
		mkg := emac.Sum(nil)
		cdata := Maccheck{datafilenode123, mkg}
		marshalcdata, err := json.Marshal(cdata)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(path, marshalcdata)
		h++

	}
	filemeta := Filemetadata{identifier, enckey, Hashkey, iv123}

	var inodefile12 Inode
	uuidfileinode := uuid.New()
	inodefile12 = Inode{inodefile.Size, uuidfileinode, inodefile.Doublepntr}
	jsndatafilenode, err := json.Marshal(&inodefile12)
	if err != nil {
		return err
	}
	ivfilenode := make([]byte, userlib.BlockSize)
	datafilenode := make([]byte, len(ivfilenode)+len(jsndatafilenode))
	ivfilenode = datafilenode[:userlib.BlockSize]

	copy(ivfilenode, completedata[:userlib.BlockSize])

	encryptfilenode := userlib.CFBEncrypter(enckey, ivfilenode)
	encryptfilenode.XORKeyStream(datafilenode[userlib.BlockSize:], jsndatafilenode)
	emac12 := userlib.NewHMAC(Hashkey)
	emac12.Write(datafilenode)
	mn := emac12.Sum(nil)
	cdata5, err := json.Marshal(Maccheck{datafilenode, mn})
	if err != nil {
		return err
	}
	userlib.DatastoreSet("working/"+identifier.String(), cdata5)
	//fmt.Println("working                                    working/" + identifier.String())
	err = Datastoresenddata(*userdata)
	if err != nil {
		return err
	}
	//send encrypted data to datastore

	// for i := 0; i < length; i++ {
	// 	if i%32 == 0 {
	// 		j++
	// 		h = 0
	// 	}
	// 	h++
	// 	encrypt := userlib.CFBEncrypter(enckey, ivinode)
	// 	encrypt.XORKeyStream(completedata[userlib.BlockSize:], data[(i*configBlockSize):((i+1)*configBlockSize)])
	// 	ivinode = completedata[(len(completedata) - userlib.BlockSize):]
	// 	fmt.Println("complete data  \n\n\n\n\n\n     ", completedata)
	// 	inodefile.Doublepntr[j][h] = bytesToUUID(userlib.RandomBytes(16)).String()

	// 	path = "files" + "/" + inodefile.Doublepntr[j][i]
	// 	datatosend := completedata[(i * configBlockSize):((i + 1) * configBlockSize)]
	// 	fmt.Println("datatosend          ", datatosend)
	// 	datafilenode123, err := json.Marshal(datatosend)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	emacdatatosend := []byte((string)(datafilenode123) + inodefile.Doublepntr[j][i])
	// 	emac := userlib.NewHMAC(Hashkey)
	// 	emac.Write(emacdatatosend)
	// 	cdata := Maccheck{datafilenode123, emac.Sum(nil)}
	// 	marshalcdata, err := json.Marshal(cdata)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	userlib.DatastoreSet(path, marshalcdata)

	// }
	// jsndatafilenode, err := json.Marshal(inodefile)
	// if err != nil {
	// 	return err
	// }

	// datafilenode12 := make([]byte, len(ivinode)+len(jsndatafilenode))

	// fmt.Println(ivinode)
	// copy(datafilenode12[:userlib.AESKeySize], ivinode)
	// encryptfilenode := userlib.CFBEncrypter(enckey, ivinode)
	// fmt.Println("encryption filenode", encryptfilenode)
	// encryptfilenode.XORKeyStream(datafilenode12[userlib.BlockSize:], jsndatafilenode)

	// emac12 := userlib.NewHMAC(Hashkey)
	// emac12.Write(datafilenode12)
	// fmt.Println("data encrypted \n", datafilenode12)
	// cdata5, err := json.Marshal(Maccheck{datafilenode12, emac12.Sum(nil)})
	// if err != nil {
	// 	return err
	// }

	// userlib.DatastoreSet("working/"+identifier.String(), cdata5)

	if isCreated == true {
		userdata.Owned[filename] = filemeta
	}
	if isShared == true {
		userdata.Shared[filename] = filemeta
	}
	err = Datastoresenddata(*userdata)
	//fmt.Println("size", inodefile.Doublepntr[0][0])
	//fmt.Println("size", inodefile.Doublepntr[0][1])
	//fmt.Println("size", inodefile.Doublepntr[0][2])
	//fmt.Println("size", inodefile.Doublepntr[1][1])
	return err
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {

	//check user datastructure for tampering
	enckey := userdata.Password[userlib.AESKeySize:]
	mackey := userdata.Password[:userlib.AESKeySize]
	mac := userlib.NewHMAC(mackey)
	//fmt.Println(userdata.Username)
	mac.Write(userdata.Username)
	pathforuserd := "users/datastruct/" + bytesToUUID(mac.Sum(nil)).String()
	// mac123 := userlib.NewHMAC([]byte("659"))
	// mac123.Write([]byte("123"))

	received, done := userlib.DatastoreGet(pathforuserd)

	if !done {
		return nil, errors.New("user not found")
	}

	var checkmac Maccheck
	err = json.Unmarshal(received, &checkmac)
	if err != nil {
		return nil, errors.New("failed to unmarshal data")
	}

	emac := userlib.NewHMAC(mackey)
	emac.Write(checkmac.Realdata)
	hemac := emac.Sum(nil)

	checkok := userlib.Equal(hemac, checkmac.Checkmac)
	if checkok == false {
		return nil, errors.New("data is corrupted")
	}

	var data12 User
	completedata := make([]byte, len(checkmac.Realdata[userlib.BlockSize:]))
	iv := checkmac.Realdata[:userlib.BlockSize]
	decrypt := userlib.CFBDecrypter(enckey, iv)
	decrypt.XORKeyStream(completedata, checkmac.Realdata[userlib.BlockSize:])
	err = json.Unmarshal(completedata, &data12)
	if err != nil {
		return nil, errors.New("cannot unmarshal data")
	}
	var isShared bool
	file, isCreated := data12.Owned[filename]
	if !isCreated {
		file, isShared = data12.Shared[filename]
		if !isShared {
			return nil, errors.New("Filename invalid or access not permitted")
		}
	}
	fileenckey := file.Enkey
	filehashkey := file.Hashkey
	fileidentifier := file.Identifier

	//get inode file from datastore
	//change file data node information
	fileinodeinfomarshal, received12 := userlib.DatastoreGet("working/" + fileidentifier.String())
	//fmt.Println(fileidentifier.String())
	if received12 == false {
		return nil, errors.New("cant fetch data")
	}

	var cdata123 Maccheck
	err = json.Unmarshal(fileinodeinfomarshal, &cdata123)
	if err != nil {
		return nil, err
	}

	emacinode := userlib.NewHMAC(filehashkey)
	emacinode.Write(cdata123.Realdata)
	hemac123 := emacinode.Sum(nil)

	checkok12 := userlib.Equal(hemac123, cdata123.Checkmac)
	if checkok12 == false {
		return nil, errors.New("data is corrupted")
	}

	var inodefile Inode
	completedata1 := make([]byte, len(cdata123.Realdata[userlib.BlockSize:]))
	ivinode := cdata123.Realdata[:userlib.BlockSize]
	decryptinode := userlib.CFBDecrypter(fileenckey, ivinode)
	decryptinode.XORKeyStream(completedata1, cdata123.Realdata[userlib.BlockSize:])
	//fmt.Println("dekh le size hai", inodefile.Size)
	err = json.Unmarshal(completedata1, &inodefile)
	//fmt.Println("                   ", offset, "                  ", inodefile.Size)
	if offset > inodefile.Size {
		return nil, errors.New("offset out of bounds")
	}
	//fmt.Println(offset/32, "    ", offset%32)
	pathtoblock := "files/" + inodefile.Doublepntr[offset/32][offset%32]
	//fmt.Println(pathtoblock)
	var checkmac12 Maccheck
	jsondata, ok := userlib.DatastoreGet(pathtoblock)
	if ok == false {
		return nil, errors.New("data not found")
	}

	err = json.Unmarshal(jsondata, &checkmac12)
	if err != nil {
		return nil, errors.New("cannot unmarshal data")
	}
	gmcfgh := []byte(string(checkmac12.Realdata) + inodefile.Doublepntr[offset/32][offset%32])
	ema12c := userlib.NewHMAC(filehashkey)
	ema12c.Write(gmcfgh)
	hem12ac := ema12c.Sum(nil)

	checkok124 := userlib.Equal(hem12ac, checkmac12.Checkmac)
	if checkok124 == false {
		return nil, errors.New("data is corrupted")
	}

	//decryptblock
	var realdata []byte
	//fmt.Println(checkmac12.Realdata)
	//fmt.Println(len(checkmac12.Realdata))
	err = json.Unmarshal(checkmac12.Realdata, &realdata)

	completedata12 := make([]byte, len(realdata[userlib.BlockSize:]))
	ivinode12 := realdata[:userlib.BlockSize]
	decrypt124 := userlib.CFBDecrypter(fileenckey, ivinode12)
	decrypt124.XORKeyStream(completedata12, realdata[userlib.AESKeySize:])

	return completedata12, err
}

//Packet hj
type Packet struct {
	// Pointer to sharingRecord
	Record sharingRecord
	// RSA Signature
	// Necessary for secure encryption of data when sharing with other users
	RSA []byte
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {

	//check permission first
	enckey := userdata.Password[userlib.AESKeySize:]
	mackey := userdata.Password[:userlib.AESKeySize]
	mac := userlib.NewHMAC(mackey)
	//fmt.Println(userdata.Username)
	mac.Write(userdata.Username)
	pathforuserd := "users/datastruct/" + bytesToUUID(mac.Sum(nil)).String()
	//fmt.Println(pathforuserd)
	//fmt.Println([]byte("123"))
	mac123 := userlib.NewHMAC([]byte("659"))
	mac123.Write([]byte("123"))
	//fmt.Println("jhgtf", mac123.Sum(nil))

	received, done := userlib.DatastoreGet(pathforuserd)

	if !done {
		return "", errors.New("user not found")
	}

	var checkmac Maccheck
	err = json.Unmarshal(received, &checkmac)
	if err != nil {
		return "", errors.New("failed to unmarshal data")
	}

	emac := userlib.NewHMAC(mackey)
	emac.Write(checkmac.Realdata)
	hemac := emac.Sum(nil)

	checkok := userlib.Equal(hemac, checkmac.Checkmac)
	if checkok == false {
		return "", errors.New("data is corrupted")
	}

	var data12 User
	completedata := make([]byte, len(checkmac.Realdata[userlib.BlockSize:]))
	iv := checkmac.Realdata[:userlib.BlockSize]
	decrypt := userlib.CFBDecrypter(enckey, iv)
	decrypt.XORKeyStream(completedata, checkmac.Realdata[userlib.BlockSize:])
	err = json.Unmarshal(completedata, &data12)
	if err != nil {
		return "", errors.New("cannot unmarshal data")
	}
	var isShared bool
	file, isCreated := data12.Owned[filename]
	if !isCreated {
		file, isShared = data12.Shared[filename]
		if !isShared {
			return "", errors.New("Filename invalid or access not permitted")
		}
	}

	jsonfile, err := json.Marshal(file)
	if err != nil {
		return "", errors.New("cant marshal data")
	}
	recvpubkey, check := userlib.KeystoreGet(recipient)
	if !check {
		return "", errors.New("recipient not found")
	}
	//fmt.Println("JSONFILE    ", jsonfile)
	//rsa encryption
	rsafile, err := userlib.RSAEncrypt(&recvpubkey, jsonfile, []byte(""))
	if err != nil {
		return "", errors.New("cannot encrypt data")
	}
	//fmt.Println("rsafile    ", rsafile)
	rsasign, err := userlib.RSASign(&userdata.Pkey, rsafile)
	if err != nil {
		return "", errors.New("cannot sign")
	}
	//fmt.Println("sign      ", rsasign)
	datatoshare := sharingRecord{rsafile}
	packet := Packet{datatoshare, rsasign}
	//fmt.Println(datatoshare)
	marshaldatatoshare, err := json.Marshal(packet)
	convrttostring := string(marshaldatatoshare)
	//fmt.Println("datatoshare     ", datatoshare)
	//fmt.Println("converttostring      ", convrttostring)
	//fmt.Println("senderpublickey     ", userdata.Pkey.PublicKey)
	return convrttostring, err
}

// ReceiveFile : Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	var err error
	//fmt.Println("converttostring     ", msgid)
	jsonmarshal := []byte(msgid)

	var packet Packet
	err = json.Unmarshal(jsonmarshal, &packet)
	if err != nil {
		return errors.New("cannot unmarshal")
	}
	//fmt.Println("datatoshare     ", packet)

	rsapubkey, check := userlib.KeystoreGet(sender)
	if !check {
		return errors.New("cannot get sender public key")
	}
	//fmt.Println("senderkey    ", rsapubkey)
	rsaverify := userlib.RSAVerify(&rsapubkey, packet.Record.Sharedata, packet.RSA)
	if rsaverify != nil {
		return errors.New("user authentication fail")
	}

	decryptdata, err := userlib.RSADecrypt(&userdata.Pkey, packet.Record.Sharedata, []byte(""))
	if err != nil {
		return errors.New("cannot decrypt data")

	}

	var fileinfo Filemetadata

	err = json.Unmarshal(decryptdata, &fileinfo)
	if err != nil {
		return errors.New("cannot unmarshal")

	}

	userdata.Shared[filename] = fileinfo
	err = Datastoresenddata(*userdata)
	if err != nil {
		return err
	}
	return err
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	enckey := userdata.Password[userlib.AESKeySize:]
	mackey := userdata.Password[:userlib.AESKeySize]
	mac := userlib.NewHMAC(mackey)
	//fmt.Println(userdata.Username)
	mac.Write(userdata.Username)
	pathforuserd := "users/datastruct/" + bytesToUUID(mac.Sum(nil)).String()
	mac123 := userlib.NewHMAC([]byte("659"))
	mac123.Write([]byte("123"))
	//fmt.Println("jhgtf", mac123.Sum(nil))

	received, done := userlib.DatastoreGet(pathforuserd)

	if !done {
		return errors.New("user not found")
	}

	var checkmac Maccheck
	err = json.Unmarshal(received, &checkmac)
	if err != nil {
		return errors.New("failed to unmarshal data")
	}

	emac := userlib.NewHMAC(mackey)
	emac.Write(checkmac.Realdata)
	hemac := emac.Sum(nil)

	checkok := userlib.Equal(hemac, checkmac.Checkmac)
	if checkok == false {
		return errors.New("data is corrupted")
	}

	var data User
	completedata := make([]byte, len(checkmac.Realdata[userlib.BlockSize:]))
	iv := checkmac.Realdata[:userlib.BlockSize]
	decrypt := userlib.CFBDecrypter(enckey, iv)
	decrypt.XORKeyStream(completedata, checkmac.Realdata[userlib.BlockSize:])
	err = json.Unmarshal(completedata, &data)
	if err != nil {
		return errors.New("cannot unmarshal data")
	}

	file, check := data.Owned[filename]
	if !check {
		return errors.New("user is invalid")
	}
	fileenckey := file.Enkey
	filehashkey := file.Hashkey
	fileidentifier := file.Identifier
	fileinodeinfomarshal, received12 := userlib.DatastoreGet("working/" + fileidentifier.String())
	//fmt.Println(fileidentifier.String())
	if received12 == false {
		return errors.New("cant fetch data")
	}

	var cdata123 Maccheck
	err = json.Unmarshal(fileinodeinfomarshal, &cdata123)
	if err != nil {
		return err
	}

	emacinode := userlib.NewHMAC(filehashkey)
	emacinode.Write(cdata123.Realdata)
	hemac123 := emacinode.Sum(nil)

	checkok12 := userlib.Equal(hemac123, cdata123.Checkmac)
	if checkok12 == false {
		return errors.New("data is corrupted")
	}

	var inodefile Inode
	completedata1 := make([]byte, len(cdata123.Realdata[userlib.BlockSize:]))
	ivinode := cdata123.Realdata[:userlib.BlockSize]
	decryptinode := userlib.CFBDecrypter(fileenckey, ivinode)
	decryptinode.XORKeyStream(completedata1, cdata123.Realdata[userlib.BlockSize:])
	//fmt.Println("dekh le size hai", inodefile.Size)
	err = json.Unmarshal(completedata1, &inodefile)

	newdata := make([]byte, inodefile.Size*configBlockSize)
	//fmt.Println(len(newdata))

	for i := 0; i < inodefile.Size; i++ {
		d, err19 := userdata.LoadFile(filename, i)
		copy(newdata[i*configBlockSize:(i+1)*configBlockSize], d)
		if err19 != nil {
			return errors.New("cannot revoke file")
		}

		//err29 = userdata.AppendFile(filename2, data)
	}

	userlib.DatastoreDelete("working/" + fileidentifier.String())
	_, newok := userdata.Owned[filename]
	if !newok {
		return errors.New("")
	}
	delete(userdata.Owned, filename)

	userdata.StoreFile(filename, newdata)
	return err
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Sharedata []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func Datastoresenddata(data User) (err error) {
	//data marshal
	jsndata, err := json.Marshal(&data)
	if err != nil {
		return err
	}

	//encryption
	enckey := data.Password[userlib.AESKeySize:]
	//fmt.Println("enckey  ", enckey)
	mackey := data.Password[:userlib.AESKeySize]
	//fmt.Println("mac  ", mackey)
	iv := make([]byte, userlib.BlockSize)
	completedata := make([]byte, len(iv)+len(jsndata))
	iv = completedata[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	//fmt.Println("iv used  ", iv)

	encrypt := userlib.CFBEncrypter(enckey, iv)
	//fmt.Println("encryption ", encrypt)
	encrypt.XORKeyStream(completedata[userlib.BlockSize:], jsndata)
	emac := userlib.NewHMAC(mackey)
	emac.Write(completedata)
	//fmt.Println("data encrypted \n", completedata)
	cdata := Maccheck{completedata, emac.Sum(nil)}

	//fmt.Println("emac sum", emac.Sum(nil))
	//pathconstruct
	pathmac := userlib.NewHMAC(mackey)
	pathmac.Write(data.Username)
	//fmt.Println("username   ", data.Username)
	pathforuserd := "users/datastruct/" + bytesToUUID(pathmac.Sum(nil)).String()
	//fmt.Println(pathforuserd)
	jsnadata, err := json.Marshal(cdata)
	//fmt.Println(cdata, "\ncompletedata")
	//fmt.Println("complte mac data ", jsnadata)
	//fmt.Println("\nhgvbhnj", err)
	userlib.DatastoreSet(pathforuserd, jsnadata)
	return err

}

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {

	_, errcheck := userlib.KeystoreGet(username)
	if errcheck == true {
		return nil, errors.New("user already exist")
	}

	usermmac := userlib.NewHMAC([]byte(password))
	usermmac.Write([]byte(username))
	usermac := usermmac.Sum(nil)
	//ARGON2 Password
	argpass := userlib.Argon2Key([]byte(password), []byte(username), uint32(2*userlib.AESKeySize))

	//RSA KEYS
	rsaprikey, err := userlib.GenerateRSAKey()
	if err != nil {
		panic(err)
	}

	//used to cremap owned[string]file_metadataate owned and shared key value pair
	tempowned := make(map[string]Filemetadata)
	tempshared := make(map[string]Filemetadata)
	var data User
	data = User{usermac, argpass, *rsaprikey, tempowned, tempshared}
	//userlib.KeystoreSet(username, rsaprikey.PublicKey)

	userlib.KeystoreSet(username, rsaprikey.PublicKey)

	err = Datastoresenddata(data)
	if err != nil {
		return nil, err
	}
	return &data, err
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {

	usermmac := userlib.NewHMAC([]byte(password))
	usermmac.Write([]byte(username))
	usermac := usermmac.Sum(nil)
	argpass := userlib.Argon2Key([]byte(password), []byte(username), uint32(2*userlib.AESKeySize))
	enckey := argpass[userlib.AESKeySize:]
	mackey := argpass[:userlib.AESKeySize]
	pathmac := userlib.NewHMAC(mackey)
	pathmac.Write(usermac)
	pathforuserd := "users/datastruct/" + bytesToUUID(pathmac.Sum(nil)).String()
	//fmt.Println(pathforuserd)
	hcdata, ok := userlib.DatastoreGet(pathforuserd)
	//fmt.Println(hcdata, "\n completedata")
	if ok == false {
		return nil, errors.New("user not found")
	}
	var cdata Maccheck
	err = json.Unmarshal(hcdata, &cdata)
	if err != nil {
		return nil, err
	}

	emac := userlib.NewHMAC(mackey)
	emac.Write(cdata.Realdata)
	hemac := emac.Sum(nil)

	checkok := userlib.Equal(hemac, cdata.Checkmac)
	if checkok == false {
		return nil, errors.New("data is corrupted")
	}

	var data User
	completedata := make([]byte, len(cdata.Realdata[userlib.BlockSize:]))
	iv := cdata.Realdata[:userlib.BlockSize]
	decrypt := userlib.CFBDecrypter(enckey, iv)
	decrypt.XORKeyStream(completedata, cdata.Realdata[userlib.BlockSize:])
	err = json.Unmarshal(completedata, &data)
	return &data, err
}
