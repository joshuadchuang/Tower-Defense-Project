package client_test

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	// var datastoreMap map[UUID][]byte

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("InitUser", func() {

		// InitUser - Doesn't do anything
		Specify("InitUser: Initialize user with same username, diff password", func() {
			userlib.DebugMsg("Initializing user __.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user __.")
			alice, err = client.InitUser("alice", defaultPassword+"lol")
			Expect(err).ToNot(BeNil())
		})

		// InitUser - 15
		Specify("InitUser: User with same username exists", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice again.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		// InitUser - 15
		Specify("InitUser: Initialize user with empty username", func() {
			userlib.DebugMsg("Initializing user __.")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		// InitUser - 19
		Specify("InitUser: Initialize user with empty password", func() {
			userlib.DebugMsg("Initializing user __.")
			alice, err = client.InitUser("alice", "")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("GetUser", func() {

		// GetUser - 20
		Specify("GetUser: There is no initialized user for the given username.", func() {
			userlib.DebugMsg("Attempting to get user Alice that doesn't exist.")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		// GetUser - 20
		Specify("GetUser: Invalid user username", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to get user Alice with wrong username.")
			_, err = client.GetUser("aliced", "defaultPassword")
			Expect(err).ToNot(BeNil())
		})

		// GetUser - 20
		Specify("GetUser: Invalid user password", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to get user Alice with wrong password.")
			_, err = client.GetUser("alice", "wrongpassword")
			Expect(err).ToNot(BeNil())
		})

		// Get User - 20, 29 - **INTEGRITY TEST (29) **
		Specify("GetUser: INTEGRITY of user struct compromised.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Tampering with all entries in Datastore.")
			datastoreMap := userlib.DatastoreGetMap()
			for uuid := range datastoreMap {
				userlib.DatastoreSet(uuid, []byte("asdfajsdflja;sdljflajsdf"))
			}

			userlib.DebugMsg("Attempt to get compromised user")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		// Get User - 20, 29 - **INTEGRITY TEST (29) **
		Specify("GetUser: INTEGRITY of user struct compromised.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Tampering with all entries in Datastore.")
			datastoreMap := userlib.DatastoreGetMap()
			for uuid := range datastoreMap {
				userlib.DatastoreSet(uuid, []byte("asdfajsdflja;sdljflajsdfasdfajsdflja;sdljflajsdfasdfajsdflja;sdljflajsdfasdfajsdflja;sdljflajsdfasdfajsdflja;sdljflajsdfasdfajsdflja;sdljflajsdf"))
			}

			userlib.DebugMsg("Attempt to get compromised user")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("StoreFile", func() {
		// Basic Store File test
		Specify("StoreFile: Basic testing for single user store.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		// Store File - 2 <- basically doesn't work, just checks for storing file but not the re-storing
		Specify("StoreFile: File changes after re-storing file.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loads file")
			dataInitial, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice re-stores file %s with content: %s", aliceFile, contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice re-loads file")
			dataFinal, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(dataFinal).ToNot(Equal(dataInitial))
		})
	})

	Describe("LoadFile", func() {

		// Load File - DIDN'T WORK
		Specify("LoadFile: File to load doesn't exist in the personal namespace of the caller.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to load non-existent file")
			_, err := alice.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice tries to append to non-existed file")
			err = alice.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		// Load File - DIDN"T WORK - **INTEGRITY TEST**
		Specify("LoadFile: Tampered file should result in error when loading.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Tampering with all entries in Datastore.")
			datastoreMap := userlib.DatastoreGetMap()
			for uuid := range datastoreMap {
				userlib.DatastoreSet(uuid, []byte("asdfajsdflja;sdljflajsdf"))
			}

			userlib.DebugMsg("Attempt to load tampered file...")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		// Load File - 32 - **INTEGRITY** Duplicate
		Specify("LoadFile: Revoked access shouldn't be able to load file", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing aliceFile %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to Bob for aliceFile.")
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accept invitation from Alice for aliceFile.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loads Alice's shared file...")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes Bob's permission.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice load file...")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob attempt to load revoked file...")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		// Load File - DIDN"T WORK - **INTEGRITY TEST**
		Specify("LoadFile: Tampered file should result in error when loading.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Tampering with all entries in Datastore.")
			datastoreMap := userlib.DatastoreGetMap()
			for uuid := range datastoreMap {
				userlib.DatastoreSet(uuid, []byte("asdfajsdflja;sdljflajsdf"))
			}

			userlib.DebugMsg("Attempt to load tampered file...")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("AppendToFile", func() {

		// Append To File - DOESN"T WORK
		Specify("AppendFile: File to append doesn't exist in the personal namespace of the caller.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to append to non-existed file")
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("CreateInvitation", func() {

		// Create Invitation - 31
		Specify("CreateInvitation: When user creates invite, given filename doesn't exist in the personal namespace of the caller", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to Bob for a non_existent file.")
			_, err := alice.CreateInvitation("non_existy", "bob")
			Expect(err).ToNot(BeNil())
		})

		// Create Invitation - 13
		Specify("CreateInvitation: When user creates invite, the given recipientUsername does not exist.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to notBob for aliceFile.")
			_, err := alice.CreateInvitation(aliceFile, "notBob")
			Expect(err).ToNot(BeNil())
		})

		// Create Invitation - DOESN'T WORK
		Specify("CreateInvitation: Create invitation to yourself.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to notBob for aliceFile.")
			_, err := alice.CreateInvitation(aliceFile, "alice")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("AcceptInvitation", func() {

		// Accept Invitation - 2, 16
		Specify("AcceptInvitation: User accepts invitation that they created themselves.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing aliceFile %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing same aliceFile %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to Bob for aliceFile.")
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accept invitation from Alice for aliceFile, but Bob already has a file with same name.")
			err = alice.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		// Accept Invitation - 2
		Specify("AcceptInvitation: When recipient accepts invite, the recipient already has file with same name.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing aliceFile %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing same aliceFile %s with content: %s", aliceFile, contentOne)
			bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to Bob for aliceFile.")
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accept invitation from Alice for aliceFile, but Bob already has a file with same name.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		// Accept Invitation - 27
		Specify("AcceptInvitation: When recipient accepts invite, the invitationPtr is invalid.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing aliceFile %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to Bob for aliceFile.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accept invitation from Alice for aliceFile, but invitationPtr is invalid.")
			err = bob.AcceptInvitation("alice", uuid.New(), aliceFile)
			Expect(err).ToNot(BeNil())
		})

		// Accept Invitation - 33 - **INTEGRITY**
		Specify("AcceptInvitation: The invitation is no longer valid due to revocation.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing aliceFile %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to Bob for aliceFile.")
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes invitation to Bob for aliceFile.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accept invitation from Alice for aliceFile, but invitationPtr is invalid.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("RevokeAccess", func() {
		// Revoke Invitation - 32 - **INTEGRITY** <- for some reason
		Specify("RevokeInvitation: Filename does not exist in personal file namespace.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing aliceFile %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to Bob for aliceFile.")
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accept invitation from Alice for aliceFile.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes Bob's permission, but for a non-existent file.")
			err = bob.RevokeAccess("lol", "bob")
			Expect(err).ToNot(BeNil())
		})

		// Revoke Invitation - 32 - **INTEGRITY** again
		Specify("RevokeInvitation: Filename not shared with the recipient.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing aliceFile %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation to Bob for aliceFile.")
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accept invitation from Alice for aliceFile.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes Bob's permission, but for a non-existent file.")
			err = bob.RevokeAccess(aliceFile, "notBob")
			Expect(err).ToNot(BeNil())
		})

		// Revoke Invitation - Doesn't do anything
		Specify("RevokeInvitation: Person hasn't created invitations for anyone.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing aliceFile %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes random person's info.")
			err = alice.RevokeAccess(aliceFile, "notBob")
			Expect(err).ToNot(BeNil())
		})

		// Revoke Invitation - Doesn't do anything
		Specify("RevokeInvitation: Person hasn't created invitatons for anyone nor a file.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes random person's info.")
			err = alice.RevokeAccess("randomFile", "notBob")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("New Tests Playground", func() {

	})
})
