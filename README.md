# Tower Defense (User Secure Sharing File Management System)

## User/User Auth
```go
type User struct {
    Username   string
    Password   string
    RSADecKey  PKEDecKey
    RSASignKey DSSignKey
    SymKey     []byte
}
```

InitUser
The User structure stores essential information for confidentiality, integrity, and authentication in the form of personalized keys for securing data (in later functions).

UUID Generation: We derive the user’s UUID from a hash of the username, taking the first 16 bytes. This ensures uniqueness and is deterministic based on the username.
Symmetric Key: A symmetric key is derived using Argon2Key() with the password and hashed username as the salt. This unique key for each user is different from the one stored in the User struct and is specifically used to encrypt this User struct.
Encrypt-Then-MAC: The User struct is serialized/marshaled, encrypted, and then HMAC’ed. We derive two keys from the symmetric key using HashKDF with purposes "encrypt" and "mac".
Finally, we store the encrypted data and concatenated MAC tag in Datastore at the UUID.

GetUser
GetUser follows the reverse procedure of InitUser:

UUID and Key Derivation: The username hash (first 16 bytes) generates the UUID, and Argon2Key() (with password and username hash) generates the symmetric key.
Decryption: The MAC is validated with HashKDF-derived keys. If it passes, the ciphertext is decrypted to recover the original user struct data.

## File Operations
```go
type FileAccess struct {
    OwnerUsername       string
    FileMetaDataUUID    userlib.UUID
    FileMetaDataKey     []byte
}

type FileMetaData struct {
    Filename               string
    FileNodeHolderUUID     userlib.UUID
    FileNodeHolderKey      []byte
    AccessPermissionsMapUUID userlib.UUID
    AccessPermissionsMapKey []byte
}

type FileNodeHolder struct {
    HeadUUID  userlib.UUID
    HeadKey   []byte
    TailUUID  userlib.UUID
    TailKey   []byte
}

type FileNode struct {
    Content      []byte
    PreviousUUID userlib.UUID
    PreviousKey  []byte
}
```

StoreFile
The StoreFile function initializes a new linked list of FileNode structs if the file does not exist (DNE), using FileNodeHolder as a manager for the head and tail nodes. For existing files, it replaces the head and tail nodes with new content.

New File: Creates a FileNodeHolder and sets the initial FileNode (head) with file content. A FileNode (tail) is also initialized but remains empty and points backward to FileNode (head).
Existing File: Replaces head and tail nodes, with the tail pointing to the head.
Hierarchical Structure (“Least Privilege,” Helpful for Sharing)
FileAccess: Each user’s "access key" to the file, enabling secure retrieval of FileMetaData.
FileMetaData: Contains access to FileNodeHolder and the AccessPermissionsMap for keeping track of recipients and shared “invitations.”
FileNodeHolder: Allows for fast access to head and tail nodes, enabling efficient appending of files.
FileNode: Holds the actual data and has a “backward” pointer to the previous node. (A doubly linked list is redundant for this design.)
LoadFile
If the file exists, LoadFile retrieves the file’s content by first accessing FileAccess, FileMetaData, and FileNodeHolder from Datastore. Starting from the tail, it traverses backward through FileNode pointers until reaching the head, sequentially stacking content like a stack. The head and tail nodes in FileNodeHolder are updated and saved to Datastore to optimize space, similar to "Path Compression" in Union-Find.

AppendToFile
If the file exists, AppendToFile updates the tail node of the file by adding new content and then creates a new empty tail node that links back to the current tail node. FileNodeHolder is updated to reference this new tail, and changes are secured in Datastore.

## Sharing and Revocation
```go
type RecipientToInvitationsMap struct {
    OwnerInvitationMap map[string]Invitation
}

type Invitation struct {
    OwnerUsername      string
    FileMetaDataUUID   userlib.UUID
    FileMetaDataKey    []byte
}
```

Sending Invitations
Owner as Sender: The owner creates a new FileMetaData struct for each recipient, replicating the master FileMetaData to allow groups of people to access the same data without exposing the RecipientToInvitationsMap. Only the owner has a populated RecipientToInvitationsMap as only the owner can revoke access.

UUID and Encryption: The FileMetaData struct for the recipient is encrypted, stored in Datastore with a random UUID and key. An Invitation struct containing the FileMetaData UUID and key is created, encrypted, signed with the owner’s private signing key, and stored in Datastore.
Key and MAC: The symmetric key is encrypted with the recipient’s public key and concatenated with the ciphertext.
Non-Owner as Sender: The non-owner user shares their own FileMetaData following the same encryption and signing steps as above.

Accepting Invitations
The recipient verifies the invitation’s structure, decrypts the symmetric key with their private key, and decrypts the invitation data. This decrypted Invitation serves as the recipient’s FileAccess, enabling access to the associated FileMetaData struct.

Revoking Users
The owner revokes a user’s access by:

Removing the Invitation: The owner locates the recipient’s invitation in RecipientToInvitationsMap and removes it.
Re-encryption: New keys and UUIDs are assigned to remaining users for FileMetaData and FileNodeHolder, invalidating any data the revoked user or adversary may have recorded.

