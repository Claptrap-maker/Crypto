package main

import (
	"bufio"
	"github.com/fatih/color"
	"io"
	"kursach/pkg/blowfish"
	"kursach/pkg/ntru"
	"kursach/pkg/ntru/params"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var Users []string
var Files []string
var Samples []string
var Directories []string
var FILE File

func CreateNewNTRUEncryptClient(name string) {
	user, err := os.Create(filepath.Join(UsersPath, name))
	if err != nil {
		log.Println(err)
		return
	}
	defer user.Close()

	keyPair, err := ntru.GenerateKey(Reader, params.EES1499EP1)
	if err != nil {
		log.Println(err)
		return
	}

	publicKey := keyPair.PublicKey.Bytes()
	UserNTRUE.PublicKey = &keyPair.PublicKey
	UserNTRUE.PrivateKey = keyPair
	UserNTRUE.Name = name

	_, err = user.Write(publicKey)
	if err != nil {
		log.Println(err)
		return
	}
}

func CreateNewBlowfishClient(name string) {
	nameOfClient := name
	constants, err := os.ReadDir(ConstantsPath)
	if err != nil {
		log.Println(err)
		return
	}

	if len(constants) == 0 {
		generatePG()
	}

	p, err := os.OpenFile(filepath.Join(ConstantsPath, "p"), os.O_RDONLY, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer p.Close()

	g, err := os.OpenFile(filepath.Join(ConstantsPath, "g"), os.O_RDONLY, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer g.Close()

	pReceiver := bufio.NewReader(p)
	gReceiver := bufio.NewReader(g)

	P, err := io.ReadAll(pReceiver)
	if err != nil {
		log.Println(err)
		return
	}

	G, err := io.ReadAll(gReceiver)
	if err != nil {
		log.Println(err)
		return
	}
	publicKey, privateKey := blowfish.GenerateKeyPair(P, G)

	UserBLOWFISH.PublicKey = publicKey
	UserBLOWFISH.PrivateKey = privateKey
	UserBLOWFISH.Name = nameOfClient

	client, err := os.OpenFile(filepath.Join(UsersPath, UserBLOWFISH.Name), os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Println(err)
		return
	}
	defer client.Close()

	_, err = client.Write(UserBLOWFISH.PublicKey)
	if err != nil {
		log.Println(err)
		return
	}
}

func RefreshSampleFiles(dir string) {
	Samples = nil
	fileSamples, err := os.ReadDir(dir)
	if err != nil {
		log.Println(err)
		return
	}

	for _, v := range fileSamples {
		Samples = append(Samples, v.Name())
	}
}

// TODO написать функцию RefreshSampleFiles, которая будет обновлять список файлов, доступных для отправки. Не забудь на строках 117 и 122 этого файла обнулять Files!
func RefreshFiles(algorithm *string) []string {
	//filesFromServer, err := os.ReadDir(whatFiles)
	//if err != nil {
	//	log.Println(err)
	//	return nil
	//}

	senderDirNtrue, err := os.ReadDir(filepath.Join(EncFilesPath, DirectoryNtrue.Name))
	if err != nil {
		log.Println(err)
		return nil
	}
	senderDirBlowfish, err := os.ReadDir(filepath.Join(EncFilesPath, DirectoryBlowfish.Name))
	if err != nil {
		log.Println(err)
		return nil
	}

	switch *algorithm {
	case "NTRUENCRYPT":
		Files = nil
		for _, v := range senderDirNtrue {
			if !slices.Contains(Files, v.Name()) && strings.Contains(v.Name(), ".") {
				Files = append(Files, v.Name())
			}
		}
	case "BLOWFISH":
		Files = nil
		for _, v := range senderDirBlowfish {
			if !slices.Contains(Files, v.Name()) && strings.Contains(v.Name(), ".") {
				Files = append(Files, v.Name())
			}
		}
	}

	return Files

}

func RefreshUsers(currentUser string) ([]string, []string) {
	usersFromServer, err := os.ReadDir(UsersPath)
	if err != nil {
		log.Println(err)
	}

	dataFromServer, err := os.ReadDir(EncFilesPath)
	if err != nil {
		log.Println(err)
		return nil, nil
	}

	for _, v := range usersFromServer {
		if (!slices.Contains(Users, v.Name())) && (v.Name() != currentUser) {
			Users = append(Users, v.Name())
		}
	}

	for _, v := range dataFromServer {
		if (!slices.Contains(Directories, v.Name())) && (v.Name() != UserBLOWFISH.Name) {
			Directories = append(Directories, v.Name())
		}
	}

	return Users, Directories
}

func UploadFileNTRUEncrypt(nameOfReceiver, nameOfFile string) {
	var partSize int64 = 247

	in, err := os.OpenFile(filepath.Join(UsersPath, nameOfReceiver), os.O_RDONLY, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer in.Close()

	publicKeyReceiver, err := io.ReadAll(in)
	if err != nil {
		log.Println(err)
		return
	}

	publicKey, err := ntru.NewPublicKey(publicKeyReceiver)
	if err != nil {
		log.Println(err)
		return
	}

	err = EncryptNtrue(nameOfFile, publicKey, partSize)
	if err != nil {
		log.Println(err)
		return
	}
	color.Green("Файл загружен")

}

func DownloadFileNTRUEncrypt(nameOfFile string) {
	var partSize int64
	partSize = 2062

	file, err := os.OpenFile(filepath.Join(EncFilesPath, DirectoryNtrue.Name, nameOfFile), os.O_RDONLY, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer file.Close()

	privateKey := UserNTRUE.PrivateKey

	err = DecryptNtrue(file, nameOfFile, privateKey, partSize)
	if err != nil {
		log.Println(err)
		return
	}
	color.Green("Файл скачан")
}

func UploadFileBlowfish(nameOfReceiver, nameOfFile string) {
	inFile, err := os.OpenFile(filepath.Join(UsersPath, nameOfReceiver), os.O_RDONLY, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer inFile.Close()

	publicKeyReceiver, err := io.ReadAll(inFile)
	if err != nil {
		log.Println(err)
		return
	}

	inP, err := os.OpenFile(filepath.Join(ConstantsPath, "p"), os.O_RDONLY, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer inP.Close()

	p, err := io.ReadAll(inP)
	if err != nil {
		log.Println(err)
		return
	}

	key := blowfish.GetCommonSecretKey(publicKeyReceiver, UserBLOWFISH.PrivateKey, p)

	bf := blowfish.NewBlowfish(key)

	err = EncryptBlowfish(nameOfFile, key, bf)
	if err != nil {
		log.Println(err)
		return
	}
	color.Green("Файл загружен")

}

func DownloadFileBlowfish(nameOfFile string) {
	senderPublicKey, err := os.OpenFile(filepath.Join(UsersPath, DirectoryBlowfish.Name), os.O_RDONLY, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer senderPublicKey.Close()

	publicKeyReceiver, err := io.ReadAll(senderPublicKey)
	if err != nil {
		log.Println(err)
		return
	}

	p, err := os.OpenFile(filepath.Join(ConstantsPath, "p"), os.O_RDONLY, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer p.Close()

	P, err := io.ReadAll(p)
	if err != nil {
		log.Println(err)
		return
	}

	key := blowfish.GetCommonSecretKey(publicKeyReceiver, UserBLOWFISH.PrivateKey, P)

	bf := blowfish.NewBlowfish(key)

	file, err := os.OpenFile(filepath.Join(EncFilesPath, DirectoryBlowfish.Name, nameOfFile), os.O_RDONLY, 0)
	if err != nil {
		log.Println(err)
		return
	}
	defer file.Close()

	err = DecryptBlowFish(file, nameOfFile, key, bf)
	if err != nil {
		log.Println(err)
		return
	}
	color.Green("Файл скачан")
}

func generatePG() {
	p, err := os.Create(filepath.Join(ConstantsPath, "p"))
	if err != nil {
		log.Println(err)
		return
	}
	defer p.Close()

	g, err := os.Create(filepath.Join(ConstantsPath, "g"))
	if err != nil {
		log.Println(err)
		return
	}
	defer g.Close()

	P, G := blowfish.GetCommonPrimeNumbers()

	_, err = p.Write(P)
	if err != nil {
		log.Println(err)
		return
	}

	_, err = g.Write(G)
	if err != nil {
		log.Println(err)
		return
	}
}
