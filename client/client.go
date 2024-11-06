package client

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	// "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username    string
	Password    string
	PrivDecKey  userlib.PKEDecKey
	PrivSignKey userlib.DSSignKey
	SymKey      []byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileAccess struct {
	OwnerUsername    string
	FileMetaDataUUID userlib.UUID
	FileMetaDataKey  []byte
}

type FileMetaData struct {
	Filename                 string
	FileNodeHolderUUID       userlib.UUID
	FileNodeHolderKey        []byte
	AccessPermissionsMapUUID userlib.UUID
	AccessPermissionsMapKey  []byte
}

type FileNodeHolder struct {
	HeadUUID userlib.UUID
	HeadKey  []byte
	TailUUID userlib.UUID
	TailKey  []byte
}

type FileNode struct {
	Content      []byte
	PreviousUUID userlib.UUID
	PreviousKey  []byte
}

type RecipientToInvitationsMap struct {
	// Owner's map of (RecipientUsername:Invitation)
	OwnerInvitationMap map[string]Invitation
}

// Note how this is the same structure as "FileAccess!"
// -- Every user will get create their own copy of FileAccess based on this invitation, but their FileAccess will point to the FileMetaData  in this invitation that is "shared" amongst a group
// -- Non-owner -> share with new user: Non-owners with access will share their same FileMetaData to other users, thus creating groups. If they get their access revoked, whole group gets access revoked
// -- Owner -> share with new User: Owner will share a "new" invitation to somethey they "directly" want to share.
type Invitation struct {
	OwnerUsername    string
	FileMetaDataUUID userlib.UUID
	FileMetaDataKey  []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

// -------------------------------------------------------------------------------------
// HELPER FUNCTIONS
// -------------------------------------------------------------------------------------

func SymEncThenMac(sourceKey []byte, plaintext []byte) (cipherTextAndMac []byte, err error) {
	encryptPurpose, err := json.Marshal("encrypt")
	if err != nil {
		return nil, errors.New("cannot serialize the string _encrypt_")
	}
	macPurpose, err := json.Marshal("mac")
	if err != nil {
		return nil, errors.New("cannot serialize the string _mac_")
	}
	encryptSymKey, err := userlib.HashKDF(sourceKey, encryptPurpose)
	if err != nil {
		return nil, errors.New("cannot derive encryptSymKey from sourceKey")
	}
	macKey, err := userlib.HashKDF(sourceKey, macPurpose)
	if err != nil {
		return nil, errors.New("cannot derive macKey from sourceKey")
	}
	iv := userlib.RandomBytes(16)

	ciphertext := userlib.SymEnc(encryptSymKey[0:16], iv, plaintext)
	tag, err := userlib.HMACEval(macKey[0:16], ciphertext)
	if err != nil {
		return nil, errors.New("cannot HMAC ciphertext")
	}
	encryptThenMac := append(ciphertext, tag...)

	return encryptThenMac, nil
}

func SymDecThenDemac(sourceKey []byte, cipherTextAndMac []byte) (plaintext []byte, err error, ok bool) {
	macLen := 64
	if len(cipherTextAndMac) <= 64 {
		return nil, errors.New("datastore output length was <64 bytes, definitely tampered with"), false
	}
	ciphertextLen := len(cipherTextAndMac) - macLen

	ciphertext := cipherTextAndMac[:ciphertextLen]
	tag := cipherTextAndMac[ciphertextLen:]

	encryptPurpose, err := json.Marshal("encrypt")
	if err != nil {
		return nil, errors.New("cannot serialize the string _decrypt_"), false
	}
	macPurpose, err := json.Marshal("mac")
	if err != nil {
		return nil, errors.New("cannot serialize the string _mac_"), false
	}
	decryptSymKey, err := userlib.HashKDF(sourceKey, encryptPurpose)
	if err != nil {
		return nil, errors.New("cannot derive decryptSymKey from sourceKey"), false
	}
	macKey, err := userlib.HashKDF(sourceKey, macPurpose)
	if err != nil {
		return nil, errors.New("cannot derive macKey from sourceKey"), false
	}

	refTag, err := userlib.HMACEval(macKey[0:16], ciphertext)
	if err != nil {
		return nil, errors.New("refTag could not be generated"), false
	}
	if !userlib.HMACEqual(refTag, tag) {
		return nil, errors.New("MAC tags did not match"), false
	}

	decryptThenDemac := userlib.SymDec(decryptSymKey[0:16], ciphertext)
	return decryptThenDemac, nil, true
}

func RetrieveFileAccessAndMetaData(userdata *User, filename string) (fileAccess *FileAccess, fileMetaData *FileMetaData, err error) {
	fmt.Println("Accessed retrieve file access helper func")
	fmt.Println("Accessed retrieve file access helper func", userdata.Username)

	fileAccessUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + strconv.Itoa(len(filename)) + userdata.Username + strconv.Itoa(len(userdata.Username))))[:16])
	fmt.Println("asdfasdf")
	if err != nil {
		return nil, nil, err
	}

	fmt.Println("go")

	encFileAccessBytes, exists := userlib.DatastoreGet(fileAccessUUID)
	if !exists {
		return nil, nil, errors.New("fileAccess DNE")
	}

	fmt.Println("got fileaccessuuid????")

	fileAccessBytes, err, ok := SymDecThenDemac(userdata.SymKey, encFileAccessBytes)
	if !ok || err != nil {
		return nil, nil, fmt.Errorf("fileAccess integrity compromised: %v", err)
	}

	err = json.Unmarshal(fileAccessBytes, &fileAccess)
	if err != nil {
		return nil, nil, err
	}

	fileMetaDataUUID := fileAccess.FileMetaDataUUID
	fileMetaDataKey := fileAccess.FileMetaDataKey

	encFileMetaDataBytes, ok := userlib.DatastoreGet(fileMetaDataUUID)
	if !ok {
		return nil, nil, errors.New("fileMetaData DNE")
	}

	fileMetaDataBytes, err, ok := SymDecThenDemac(fileMetaDataKey, encFileMetaDataBytes)
	if !ok || err != nil {
		return nil, nil, errors.New("fileMetaData integrity has been compromised")
	}

	err = json.Unmarshal(fileMetaDataBytes, &fileMetaData)
	if err != nil {
		return nil, nil, err
	}

	return fileAccess, fileMetaData, nil
}

// func CheckUserExists()

// -------------------------------------------------------------------------------------
// IMPLEMENTATION/ACTION FUNCTIONS
// -------------------------------------------------------------------------------------

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Step 1. Check if the username and password empty
	if username == "" {
		return nil, errors.New("username is empty")
	}
	if password == "" {
		return nil, errors.New("password is empty")
	}

	// Step 2. Create user UUID (for Datastore)
	usernameToBytes, err := json.Marshal(username)
	if err != nil {
		return nil, errors.New("cannot serialize username")
	}
	usernameBytesToHash := userlib.Hash(usernameToBytes)
	usernameHashToUUID, err := uuid.FromBytes(usernameBytesToHash[0:16])
	if err != nil {
		return nil, errors.New("cannot turn user Hash into UUID")
	}

	// Step 3. Error if user UUID in Datastore
	_, ok := userlib.DatastoreGet(usernameHashToUUID)
	if ok {
		return nil, errors.New("User already exists in Datastore")
	}

	// Step 4. Initialize the user's User struct w/ username and password
	var userdata User
	userdata.Username = username
	userdata.Password = password

	// Step 5. Create public/private encryption keys, and digital signatures, add to User struct
	pkeenckey, pkedeckey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("failed to generate encryption key pair")
	}

	userlib.KeystoreSet(username+"pubEnc", pkeenckey)
	userdata.PrivDecKey = pkedeckey

	dssignkey, dsverifykey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("failed to generate sign key pair")
	}
	userlib.KeystoreSet(username+"pubVerify", dsverifykey)
	userdata.PrivSignKey = dssignkey

	// Step 6. Create symmetric-key encryption, add to User struct
	userdata.SymKey = userlib.RandomBytes(16)

	// Step 7. EncryptThenMac User struct
	userdataBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New("cannot serialize userdata struct")
	}

	passwordToBytes, err := json.Marshal(password)
	if err != nil {
		return nil, errors.New("cannot serialize password")
	}
	passDerivedSymKey := userlib.Argon2Key(passwordToBytes, usernameBytesToHash, 16)

	userdataBytesEncAndMac, err := SymEncThenMac(passDerivedSymKey, userdataBytes)
	if err != nil {
		return nil, errors.New("cannot encryptThenMac userdataBytes")
	}

	// Step 9. Store both encrypted data and MAC in Datastore
	userlib.DatastoreSet(usernameHashToUUID, userdataBytesEncAndMac)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Step 1. Create user UUID (to get user struct from Datastore)
	usernameToBytes, err := json.Marshal(username)
	if err != nil {
		return nil, errors.New("cannot serialize username")
	}
	usernameBytesToHash := userlib.Hash(usernameToBytes)
	usernameHashToUUID, err := uuid.FromBytes(usernameBytesToHash[0:16])
	if err != nil {
		return nil, errors.New("cannot turn user Hash into UUID")
	}

	// Step 2. Check that there is initialized user for given username
	userdataEncAndMac, ok := userlib.DatastoreGet(usernameHashToUUID)
	if !ok {
		return nil, errors.New("no initialized user for given username")
	}

	// Step 3. DecryptAndDemac
	passwordToBytes, err := json.Marshal(password)
	if err != nil {
		return nil, errors.New("cannot serialize password")
	}
	passDerivedSymKey := userlib.Argon2Key(passwordToBytes, usernameBytesToHash, 16)

	decUserData, err, ok := SymDecThenDemac(passDerivedSymKey, userdataEncAndMac)
	if err != nil || !ok {
		return nil, errors.New("decryption did not work")
	}

	// Step 4: Get the decryption, return it
	var userdata User
	userdataptr = &userdata
	err = json.Unmarshal(decUserData, userdataptr)
	if err != nil {
		return nil, errors.New("decryption cannot be unserialized")
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Step 1: Create head and tail FileNodes structs, store into Datastore
	var headNode FileNode
	var tailNode FileNode

	headNodeUUID := uuid.New()
	headNodeKey := userlib.RandomBytes(16)
	headNode.Content = content
	headNode.PreviousUUID = uuid.Nil
	headNode.PreviousKey = nil

	tailNodeUUID := uuid.New()
	tailNodeKey := userlib.RandomBytes(16)
	tailNode.Content = nil
	tailNode.PreviousUUID = headNodeUUID
	tailNode.PreviousKey = headNodeKey

	headNodeBytes, err := json.Marshal(headNode)
	if err != nil {
		return errors.New("cannot serialize userdata struct")
	}
	tailNodeBytes, err := json.Marshal(tailNode)
	if err != nil {
		return errors.New("cannot serialize userdata struct")
	}

	encHeadNodeBytes, err := SymEncThenMac(headNodeKey, headNodeBytes)
	if err != nil {
		return err
	}
	encTailNodeBytes, err := SymEncThenMac(tailNodeKey, tailNodeBytes)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(headNodeUUID, encHeadNodeBytes)
	userlib.DatastoreSet(tailNodeUUID, encTailNodeBytes)

	// Step 2: Get FileAccess from Datastore - retrival of possible existing file in Datastore
	fileAccessUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + strconv.Itoa(len(filename)) + userdata.Username + strconv.Itoa(len(userdata.Username))))[:16])
	if err != nil {
		return err
	}

	// Step 3: Deal with two cases, file DNE (create new file accesses) or file already exists in Datastore
	encFileAccessBytes, exists := userlib.DatastoreGet(fileAccessUUID)

	// Case 1 ("File doesn't exist"): create new file - Create access structure BOTTOM -> UP
	if !exists {
		// Initialize new RecipientToInvitationsMap struct
		accessPermissionsMapUUID := uuid.New()
		accessPermissionsMapKey := userlib.RandomBytes(16)

		var accessPermissionsMap RecipientToInvitationsMap
		var ownerInvitationMap map[string]Invitation
		accessPermissionsMap.OwnerInvitationMap = ownerInvitationMap

		accessPermissionsMapBytes, err := json.Marshal(accessPermissionsMap)
		if err != nil {
			return err
		}
		encAccessPermissionsMapBytes, err := SymEncThenMac(accessPermissionsMapKey, accessPermissionsMapBytes)
		if err != nil {
			return errors.New("failed to encrypt accessPermissionsMap")
		}
		userlib.DatastoreSet(accessPermissionsMapUUID, encAccessPermissionsMapBytes)

		// Initialize new FileNodeHolder and store in Datastore
		fileNodeHolderUUID := uuid.New()
		fileNodeHolderKey := userlib.RandomBytes(16)
		fileNodeHolder := FileNodeHolder{
			HeadUUID: headNodeUUID,
			HeadKey:  headNodeKey,
			TailUUID: tailNodeUUID,
			TailKey:  tailNodeKey,
		}

		serializedfileNodeHolder, err := json.Marshal(fileNodeHolder)
		if err != nil {
			return err
		}

		encryptedFileNodeHolder, err := SymEncThenMac(fileNodeHolderKey, serializedfileNodeHolder)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(fileNodeHolderUUID, encryptedFileNodeHolder)

		// Initalize new FileMetaData and store in Datastore
		var fileMetaData FileMetaData
		fileMetaData.Filename = filename
		fileMetaData.FileNodeHolderUUID = fileNodeHolderUUID
		fileMetaData.FileNodeHolderKey = fileNodeHolderKey
		fileMetaData.AccessPermissionsMapUUID = accessPermissionsMapUUID
		fileMetaData.AccessPermissionsMapKey = accessPermissionsMapKey

		fileMetaDataUUID := uuid.New()
		fileMetaDataKey := userlib.RandomBytes(16)
		fileMetaDataBytes, err := json.Marshal(fileMetaData)
		if err != nil {
			return err
		}

		encFileMetaDataBytes, err := SymEncThenMac(fileMetaDataKey, fileMetaDataBytes)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileMetaDataUUID, encFileMetaDataBytes)

		// Initialize new FileAcess struct and store in Datastore
		var fileAccess FileAccess
		fileAccess.OwnerUsername = userdata.Username
		fileAccess.FileMetaDataUUID = fileMetaDataUUID
		fileAccess.FileMetaDataKey = fileMetaDataKey

		fileAccessBytes, err := json.Marshal(fileAccess)
		if err != nil {
			return err
		}
		encFileAccessBytes, err := SymEncThenMac(userdata.SymKey, fileAccessBytes)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileAccessUUID, encFileAccessBytes)
		// Case 2 ("File exists"): replace fileNodes - Get access TOP -> DOWN
	} else {
		// Retrieve FileAccess
		fileAccessBytes, err, ok := SymDecThenDemac(userdata.SymKey, encFileAccessBytes)
		if !ok || err != nil {
			return errors.New("fileAccess integrity has been compromised")
		}
		var fileAccess FileAccess
		err = json.Unmarshal(fileAccessBytes, &fileAccess)
		if err != nil {
			return err
		}

		// Retrieve FileMetadata
		encFileMetaDataBytes, exists := userlib.DatastoreGet(fileAccess.FileMetaDataUUID)
		if !exists {
			return errors.New("fileMetadata DNE")
		}
		fileMetaDataBytes, err, ok := SymDecThenDemac(fileAccess.FileMetaDataKey, encFileMetaDataBytes)
		if !ok || err != nil {
			return errors.New("fileMetaData integrity has been compromised")
		}
		var fileMetaData FileMetaData
		err = json.Unmarshal(fileMetaDataBytes, &fileMetaData)
		if err != nil {
			return err
		}

		// Retrieve FileNodeHolder
		encFileNodeHolderBytes, exists := userlib.DatastoreGet(fileMetaData.FileNodeHolderUUID)
		if !exists {
			return errors.New("fileNoldHolder DNE")
		}
		fileNodeHolderBytes, err, ok := SymDecThenDemac(fileMetaData.FileNodeHolderKey, encFileNodeHolderBytes)
		if !ok || err != nil {
			return errors.New("fileNodeHolder integrity has been compromised")
		}
		var fileNodeHolder FileNodeHolder
		err = json.Unmarshal(fileNodeHolderBytes, &fileNodeHolder)
		if err != nil {
			return err
		}

		// Replace FileNodeHolder's head/tail FileNodes with new head/tail FileNodes
		fileNodeHolder.HeadUUID = headNodeUUID
		fileNodeHolder.HeadKey = headNodeKey
		fileNodeHolder.TailUUID = tailNodeUUID
		fileNodeHolder.TailKey = tailNodeKey

		// Re-encryptThenMac updated FileNodeHolder, and store back into Datastore
		fileNodeHolderBytes, err = json.Marshal(fileNodeHolder)
		if err != nil {
			return err
		}

		encFileNodeHolderBytes, err = SymEncThenMac(fileMetaData.FileNodeHolderKey, fileNodeHolderBytes)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileMetaData.FileNodeHolderUUID, encFileNodeHolderBytes)
	}

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	_, fileMetaData, err := RetrieveFileAccessAndMetaData(userdata, filename)
	if err != nil {
		return errors.New("filename DNE in user's filespace")
	}

	// Step 1: Get the current fileNodeHolder struct
	encFileNodeHolderBytes, ok := userlib.DatastoreGet(fileMetaData.FileNodeHolderUUID)
	if !ok {
		return errors.New("fileNodeHolder DNE")
	}

	fileNodeBytes, err, ok := SymDecThenDemac(fileMetaData.FileNodeHolderKey, encFileNodeHolderBytes)
	if !ok || err != nil {
		return errors.New("fileNodeHolder integrity has been compromised")
	}

	var fileNodeHolder FileNodeHolder
	err = json.Unmarshal(fileNodeBytes, &fileNodeHolder)
	if err != nil {
		return err
	}

	// Step 2: Retrieve and decrypt the obtained tailNode
	encTailNodeBytes, ok := userlib.DatastoreGet(fileNodeHolder.TailUUID)
	if !ok {
		return errors.New("tailNode DNE")
	}

	tailNodeBytes, err, ok := SymDecThenDemac(fileNodeHolder.TailKey, encTailNodeBytes)
	if !ok || err != nil {
		return errors.New("tailNode integrity has been compromised")
	}

	var tailNode FileNode
	err = json.Unmarshal(tailNodeBytes, &tailNode)
	if err != nil {
		return err
	}

	// Step 3: Update the contents of the current tailNode with the appended contents
	tailNode.Content = content
	tailNodeBytes, err = json.Marshal(tailNode)
	if err != nil {
		return err
	}

	encTailNodeBytes, err = SymEncThenMac(fileNodeHolder.TailKey, tailNodeBytes)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileNodeHolder.TailUUID, encTailNodeBytes)

	// Step 4: Create new empty tailNode
	var newTailNode FileNode
	newTailNode.PreviousUUID = fileNodeHolder.TailUUID
	newTailNode.PreviousKey = fileNodeHolder.TailKey

	fileNodeHolder.TailUUID = uuid.New()
	fileNodeHolder.TailKey = userlib.RandomBytes(16)

	newTailNodeBytes, err := json.Marshal(newTailNode)
	if err != nil {
		return err
	}

	encNewTailNodeBytes, err := SymEncThenMac(fileNodeHolder.TailKey, newTailNodeBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileNodeHolder.TailUUID, encNewTailNodeBytes)

	// Step 5: Store update fileNodeHolder in Datastore
	fileNodeHolderBytes, err := json.Marshal(fileNodeHolder)
	if err != nil {
		return err
	}

	encFileNodeHolderBytes, err = SymEncThenMac(fileMetaData.FileNodeHolderKey, fileNodeHolderBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileMetaData.FileNodeHolderUUID, encFileNodeHolderBytes)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	fmt.Println("in load file")
	usernameThing := userdata.Username
	fmt.Println("in load file", usernameThing)
	// Step 1: Use RetrieveFileAccessAndMetaData helper function to retrieve the fileAccess and fileMetaData
	_, fileMetaData, err := RetrieveFileAccessAndMetaData(userdata, filename)
	if err != nil {
		return nil, errors.New("filename DNE in user's filespace")
	}
	fmt.Println("in load file out of helper")

	// Account for multiple tail nodes, essentially collapse all the appends and return 'true content

	// Step 2: Get FileNodeHolder
	encFileNodeHolderBytes, exists := userlib.DatastoreGet(fileMetaData.FileNodeHolderUUID)
	if !exists {
		return nil, errors.New("the fileNodeHolder sturct does not exist in Datastore")
	}
	fileNodeHolderBytes, err, ok := SymDecThenDemac(fileMetaData.FileNodeHolderKey, encFileNodeHolderBytes)
	if !ok || err != nil {
		return nil, errors.New("the integrity of fileNodeHolder struct has been compromised")
	}
	var fileNodeHolder FileNodeHolder
	err = json.Unmarshal(fileNodeHolderBytes, &fileNodeHolder)
	if err != nil {
		return nil, err
	}

	// Step 3: Retrieve the tailnode from FileNodeHoler
	var tailNode FileNode
	encTailNodeBytes, exists := userlib.DatastoreGet(fileNodeHolder.TailUUID)
	if !exists {
		return nil, errors.New("tail node does not exist in Datastore")
	}
	tailNodeBytes, _, ok := SymDecThenDemac(fileNodeHolder.TailKey, encTailNodeBytes)
	if !ok {
		return nil, errors.New("integrity of tail struct has been compromised")
	}
	err = json.Unmarshal(tailNodeBytes, &tailNode)
	if err != nil {
		return nil, err
	}

	// Step 4: If there are more than one tailnode, cycle through to collapse the
	for fileNodeHolder.TailUUID != fileNodeHolder.HeadUUID {
		var prevTailNode FileNode
		encPrevTailNodeBytes, ok := userlib.DatastoreGet(tailNode.PreviousUUID)
		if !ok {
			return nil, errors.New("the previous node does not exist in Datastore")
		}
		prevTailNodeBytes, _, ok := SymDecThenDemac(tailNode.PreviousKey, encPrevTailNodeBytes)
		if !ok {
			return nil, errors.New("integrity of FileAccess struct has been compromised")
		}
		err = json.Unmarshal(prevTailNodeBytes, &prevTailNode)
		if err != nil {
			return nil, err
		}

		prevTailNode.Content = append(prevTailNode.Content, tailNode.Content...)

		userlib.DatastoreDelete(fileNodeHolder.TailUUID)

		// fileNodeHolder's tail node is now the previous node
		fileNodeHolder.TailUUID = tailNode.PreviousUUID
		fileNodeHolder.TailKey = tailNode.PreviousKey

		tailNode = prevTailNode
	}

	// Step 5: Prevent info leaking by creating a copy of the head with new uuid and key
	var newHeadNode FileNode
	newHeadNode.Content = tailNode.Content
	userlib.DatastoreDelete(fileNodeHolder.HeadUUID)
	fileNodeHolder.HeadUUID = uuid.New()
	fileNodeHolder.HeadKey = userlib.RandomBytes(16)

	// Step 6: Store updated tail (which is now the head)
	newHeadNodeBytes, err := json.Marshal(newHeadNode)
	if err != nil {
		return nil, err
	}
	encNewHeadNodeBytes, err := SymEncThenMac(fileNodeHolder.HeadKey, newHeadNodeBytes)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(fileNodeHolder.HeadUUID, encNewHeadNodeBytes)

	// Step 7: Create empty tailnode
	var emptyTailNode FileNode
	emptyTailNode.PreviousUUID = fileNodeHolder.HeadUUID
	emptyTailNode.PreviousKey = fileNodeHolder.HeadKey

	fileNodeHolder.TailUUID = uuid.New()
	fileNodeHolder.TailKey = userlib.RandomBytes(16)

	emptyTailNodeBytes, err := json.Marshal(emptyTailNode)
	if err != nil {
		return nil, err
	}
	encEmptyTailNodeBytes, err := SymEncThenMac(fileNodeHolder.TailKey, emptyTailNodeBytes)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(fileNodeHolder.TailUUID, encEmptyTailNodeBytes)

	// Step 8: Store the updated fileNodeholder back in Datastore
	fileNodeHolderBytes, err = json.Marshal(fileNodeHolder)
	if err != nil {
		return nil, err
	}

	encFileNodeHolderBytes, err = SymEncThenMac(fileMetaData.FileNodeHolderKey, fileNodeHolderBytes)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(fileMetaData.FileNodeHolderUUID, encFileNodeHolderBytes)

	return tailNode.Content, nil

	// storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	// if err != nil {
	// 	return nil, err
	// }
	// dataJSON, ok := userlib.DatastoreGet(storageKey)
	// if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	// }
	// err = json.Unmarshal(dataJSON, &content)
	// return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// GENERAL STRUCTURE:
	// 1. Generate a new FileMetaData struct
	// 2. Create a new Invitation struct
	// 3. Add the new Inv struct to the RecipientToInvitationsMap
	fmt.Println("in CreateInvitation")

	if userdata.Username == recipientUsername {
		return uuid.Nil, errors.New("you can't share a file to yourself")
	}

	publicEncKey, ok := userlib.KeystoreGet(recipientUsername + "pubEnc")
	if !ok {
		return uuid.Nil, errors.New("recipient's publicEncKey DNE")
	}

	// Step 1: Obtain the inviter's FileMetaData and FileAccess structs
	inviterFileAccess, inviterFileMetaData, err := RetrieveFileAccessAndMetaData(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}

	var invitation Invitation

	// Step 2 (Case 1): If the inviter is the file owner, create a new FileMetaData struct
	if inviterFileAccess.OwnerUsername == userdata.Username {
		fmt.Println("in if-statement-case-1")

		// Initialize the recipient's FileMetaData (FMD)
		var recipientFMD FileMetaData

		recipientFMD.Filename = inviterFileMetaData.Filename
		recipientFMD.FileNodeHolderUUID = inviterFileMetaData.FileNodeHolderUUID
		recipientFMD.FileNodeHolderKey = inviterFileMetaData.FileNodeHolderKey

		// Encrypt and store the recipient's FMD
		recipientFMDBytes, err := json.Marshal(recipientFMD)
		if err != nil {
			return uuid.Nil, err
		}

		recipientFMDkey := userlib.RandomBytes(16)
		encRecipientFMDBytes, err := SymEncThenMac(recipientFMDkey, recipientFMDBytes)
		if err != nil {
			return uuid.Nil, err
		}
		recipientFMDuuid := uuid.New()
		fmt.Println("before first datastore set")
		userlib.DatastoreSet(recipientFMDuuid, encRecipientFMDBytes)

		// Fill out invitation struct, this will give access to correct FMD
		invitation.OwnerUsername = userdata.Username
		invitation.FileMetaDataUUID = recipientFMDuuid
		invitation.FileMetaDataKey = recipientFMDkey

		// Add invite struct to RecipientToInvitationsMap
		RtIMUUID := inviterFileMetaData.AccessPermissionsMapUUID
		RtIMKey := inviterFileMetaData.AccessPermissionsMapKey
		encRtIMBytes, ok := userlib.DatastoreGet(RtIMUUID)
		if !ok {
			return uuid.Nil, errors.New("RecipientToInvitationsMap does not exist in Datastore")
		}

		RtIMBytes, err, ok := SymDecThenDemac(RtIMKey, encRtIMBytes)
		if !ok || err != nil {
			return uuid.Nil, err
		}
		fmt.Println("before creating map")
		recipientToInvitationsMap := &RecipientToInvitationsMap{}
		err = json.Unmarshal(RtIMBytes, recipientToInvitationsMap)
		fmt.Println("before checking recipientToInvitation's map unmarshaling")
		if err != nil {
			return uuid.Nil, err
		}
		fmt.Println("before assigning map to invitation")
		if recipientToInvitationsMap.OwnerInvitationMap == nil {
			recipientToInvitationsMap.OwnerInvitationMap = make(map[string]Invitation)
		}

		recipientToInvitationsMap.OwnerInvitationMap[recipientUsername] = invitation
		fmt.Println("after assigning map to invitation")
		fmt.Printf("OwnerInvitationMap contents: %+v\n", recipientToInvitationsMap.OwnerInvitationMap)

		// RecipientToInvitationMap updates to shared user file map in Datastore
		RtIMBytes, err = json.Marshal(recipientToInvitationsMap)
		if err != nil {
			return uuid.Nil, err
		}
		fmt.Println("marshal")

		encRtIMBytes, err = SymEncThenMac(inviterFileMetaData.AccessPermissionsMapKey, RtIMBytes)
		if err != nil {
			return uuid.Nil, err
		}
		fmt.Println("symencthenmac")
		fmt.Println("before datastoreSet")
		userlib.DatastoreSet(inviterFileMetaData.AccessPermissionsMapUUID, encRtIMBytes)

		// // DEBUGGING -------------------------
		// retrievedBytes, exists := userlib.DatastoreGet(inviterFileMetaData.AccessPermissionsMapUUID)
		// if !exists {
		// 	return uuid.Nil, errors.New("RecipientToInvitationsMap DNE")
		// }
		// retrievedMapBytes, err, ok := SymDecThenDemac(inviterFileMetaData.AccessPermissionsMapKey, retrievedBytes)
		// if !ok || err != nil {
		// 	return uuid.Nil, errors.New("RecipientToInvitationsMap's integrity was compromised")
		// }

		// var retrievedMap RecipientToInvitationsMap
		// err = json.Unmarshal(retrievedMapBytes, &retrievedMap)
		// if err != nil {
		// 	return uuid.Nil, err
		// }
		// fmt.Printf("Stored OwnerInvitationMap in CreateInvitation: %+v\n", retrievedMap.OwnerInvitationMap)
		// // DEBUGGING -------------------------

	} else {
		fmt.Println("in if-statement-case-2")
		// Step 3 (Case 2): If the recipient is not the file owner, share current FileMetaData struct (no need to create a new one)
		invitation.OwnerUsername = inviterFileAccess.OwnerUsername
		invitation.FileMetaDataUUID = inviterFileAccess.FileMetaDataUUID
		invitation.FileMetaDataKey = inviterFileAccess.FileMetaDataKey
	}

	fmt.Println("out of if-statement")
	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}

	// Step 4: Encrypt the Invitation struct (sym encrypt invitation, then rsa encrypt invitation) + Digital Signature
	invitationUUID := uuid.New()

	symmetricKey := userlib.RandomBytes(16)
	encData, err := SymEncThenMac(symmetricKey, invitationBytes)
	if err != nil {
		return uuid.Nil, err
	}
	encKey, err := userlib.PKEEnc(publicEncKey, symmetricKey)
	if err != nil {
		return uuid.Nil, err
	}

	digitalSig, err := userlib.DSSign(userdata.PrivSignKey, append(encKey, encData...))
	if err != nil {
		return uuid.Nil, err
	}

	// Step 5: Add digital signature (256-byte), encrypted Key (256-byte) and encrypted data to Datastore.
	EncryptedInvitation := append(append(digitalSig, encKey...), encData...)
	userlib.DatastoreSet(invitationUUID, EncryptedInvitation)

	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	fmt.Println("in AcceptInvitation")

	// Edge Cases:
	// if sender = recipient
	if senderUsername == userdata.Username {
		return errors.New("same user, can't accept own invitation")
	}
	fmt.Println("in AcceptInvitation 1")
	fileAccessUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + strconv.Itoa(len(filename)) + userdata.Username + strconv.Itoa(len(userdata.Username))))[:16])
	if err != nil {
		return err
	}
	_, exists := userlib.DatastoreGet(fileAccessUUID)
	if exists {
		return errors.New("recipient already has file with same filename")
	}

	// Step 1: Decrypt Invitation
	encAndSignedInvitation, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation DNE in Datastore")
	}

	signature := encAndSignedInvitation[:256]
	encInvitation := encAndSignedInvitation[256:]
	verifyKey, ok := userlib.KeystoreGet(senderUsername + "pubVerify")
	if !ok {
		return errors.New("sender's verify key DNE")
	}
	err = userlib.DSVerify(verifyKey, encInvitation, signature)
	if err != nil {
		return err
	}
	fmt.Println("in AcceptInvitation 2")
	encKey := encInvitation[:256]
	encInvitationBytes := encInvitation[256:]
	symmetricKey, err := userlib.PKEDec(userdata.PrivDecKey, encKey)
	if err != nil {
		return nil
	}
	invitationBytes, err, ok := SymDecThenDemac(symmetricKey, encInvitationBytes)
	if !ok || err != nil {
		return errors.New("invitation integrity has been compromised")
	}

	invitation := &Invitation{}
	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return err
	}

	fmt.Println("in AcceptInvitation 3")
	// Step 2: Create new, personal FileAccess struct for recipient
	var fileAccess FileAccess
	fileAccess.OwnerUsername = invitation.OwnerUsername
	fileAccess.FileMetaDataUUID = invitation.FileMetaDataUUID
	fileAccess.FileMetaDataKey = invitation.FileMetaDataKey

	// the personalized invitation no longer needed, since copy was stored onto personal FileAccess
	userlib.DatastoreDelete(invitationPtr)

	_, exists = userlib.DatastoreGet(fileAccess.FileMetaDataUUID)
	if !exists {
		return errors.New("Cannot access invitation's FMD, invitation was revoked.")
	}

	fileAccessBytes, err := json.Marshal(fileAccess)
	if err != nil {
		return err
	}
	encFileAccessBytes, err := SymEncThenMac(userdata.SymKey, fileAccessBytes)
	if err != nil {
		return err
	}

	fmt.Println("in AcceptInvitation 4")
	// Step 3: Store new FileAccess into Datastore (create UUID deterministically)
	userlib.DatastoreSet(fileAccessUUID, encFileAccessBytes)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	fmt.Println("in RevokeAccess")
	fileAccess, fileMetaData, err := RetrieveFileAccessAndMetaData(userdata, filename)
	if err != nil {
		return err
	}

	fmt.Println("before revokeAccess Step 1")
	// Step 1: Get user's RecipientToInvitation's sharedMap

	var sharedMap RecipientToInvitationsMap
	encSharedMapBytes, exists := userlib.DatastoreGet(fileMetaData.AccessPermissionsMapUUID)
	if !exists {
		return errors.New("shared map DNE")
	}
	sharedMapBytes, err, ok := SymDecThenDemac(fileMetaData.AccessPermissionsMapKey, encSharedMapBytes)
	if !ok || err != nil {
		return errors.New("shared map integrity compromised")
	}
	err = json.Unmarshal(sharedMapBytes, &sharedMap)
	if err != nil {
		return err
	}

	fmt.Println("before revokeAccess Step 2")
	// Step 2: Check if the recipientUsername is in the sharedMap. if it is -> get corresponding invitation
	fmt.Printf("OwnerInvitationMap contents: %+v\n", sharedMap.OwnerInvitationMap)
	invitation, ok := sharedMap.OwnerInvitationMap[recipientUsername]
	if !ok {
		return errors.New("recipientUsername DNE")
	}

	fmt.Println("before revokeAccess Step 3")
	// Step 3: Delete their "group" FileMetaData struct from Datastore AND its corresponding Invitation in sharedMap
	userlib.DatastoreDelete(invitation.FileMetaDataUUID)
	delete(sharedMap.OwnerInvitationMap, recipientUsername)
	fmt.Printf("OwnerInvitationMap contents: %+v\n", sharedMap.OwnerInvitationMap)

	fmt.Println("before revokeAccess Step 4")
	// Step 4: Update own FileMetaData's OwnerInvitationMap
	sharedMapBytes, err = json.Marshal(sharedMap)
	if err != nil {
		return err
	}
	encSharedMapBytes, err = SymEncThenMac(fileMetaData.AccessPermissionsMapKey, sharedMapBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileMetaData.AccessPermissionsMapUUID, encSharedMapBytes)

	fmt.Println("before revokeAccess Step 5")
	// Step 5: Reencrypt everything (FileNodes, FileNodeHolder) so that they RevokedUserAdversary can't do anything
	// collapse the file for ease of encryption
	_, err = userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	// get the FileNodeHolderBytes temporarily, change access keys, then put it back
	encFileNodeHolderBytes, exists := userlib.DatastoreGet(fileMetaData.FileNodeHolderUUID)
	if !exists {
		return errors.New("fileNodeHolder DNE")
	}

	fileNodeHolderBytes, err, ok := SymDecThenDemac(fileMetaData.FileNodeHolderKey, encFileNodeHolderBytes)
	if !ok || err != nil {
		return errors.New("fileNodeHolder's integrity is compromised")
	}

	userlib.DatastoreDelete(fileMetaData.FileNodeHolderUUID)
	fileMetaData.FileNodeHolderUUID = uuid.New()
	fileMetaData.FileNodeHolderKey = userlib.RandomBytes(16)

	encFileNodeHolderBytes, err = SymEncThenMac(fileMetaData.FileNodeHolderKey, fileNodeHolderBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileMetaData.FileNodeHolderUUID, encFileNodeHolderBytes)

	// write the changes to disk by updating FileMetaData on Datastore
	fileMetaDataBytes, err := json.Marshal(fileMetaData)
	if err != nil {
		return err
	}
	encFileMetaDataBytes, err := SymEncThenMac(fileAccess.FileMetaDataKey, fileMetaDataBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileAccess.FileMetaDataUUID, encFileMetaDataBytes)

	fmt.Println("before revokeAccess Step 6")
	// Step 6: Populate these changes to fileNodeHolder UUID and key for everyone else who has access
	for _, invite := range sharedMap.OwnerInvitationMap {
		var tempFileMetaData FileMetaData
		encTempFileMetaDataBytes, ok := userlib.DatastoreGet(invite.FileMetaDataUUID)
		if !ok {
			return errors.New("value at UUID does not exist")
		}
		tempFileMetaDataBytes, err, ok := SymDecThenDemac(invite.FileMetaDataKey, encTempFileMetaDataBytes)
		if !ok || err != nil {
			return errors.New("decryption and validation/verification failed")
		}
		err = json.Unmarshal(tempFileMetaDataBytes, &tempFileMetaData)
		if err != nil {
			return err
		}

		// update the info
		tempFileMetaData.FileNodeHolderUUID = fileMetaData.FileNodeHolderUUID
		tempFileMetaData.FileNodeHolderKey = fileMetaData.FileNodeHolderKey

		tempFileMetaDataBytes, err = json.Marshal(tempFileMetaData)
		if err != nil {
			return err
		}
		encTempFileMetaDataBytes, err = SymEncThenMac(invite.FileMetaDataKey, tempFileMetaDataBytes)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(invite.FileMetaDataUUID, encTempFileMetaDataBytes)

	}

	return nil
}
