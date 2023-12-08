package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"kursach/pkg/ntru"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	UsersPath     = "internal/users"
	EncFilesPath  = "internal/files/encrypted"
	DecFilesPath  = "internal/files/decrypted"
	SamplesPath   = "internal/files/samples"
	ConstantsPath = "internal/files/const"
)

type UserNtrue struct {
	Name         string
	ReceiverName string
	PrivateKey   *ntru.PrivateKey
	PublicKey    *ntru.PublicKey
}

type UserBlowfish struct {
	Name         string
	ReceiverName string
	PublicKey    []byte
	PrivateKey   []byte
}

type File struct {
	Name string
}

type Directory struct {
	Name string
}

var UserNTRUE UserNtrue
var UserBLOWFISH UserBlowfish
var DirectoryNtrue Directory
var DirectoryBlowfish Directory
var Reader = rand.Reader
var CurrentUserName string

func printTitle() {
	fmt.Println("")
	color.Cyan("\t\t\t\t\t\t\t\t|*****************************************|")
	fmt.Println("\t\t\t\t\t\t\t\t|FILE SERVER WITH NTRUENCRYPT AND BLOWFISH")
	fmt.Println("\t\t\t\t\t\t\t\t|		by Ivanova Julia			")
	color.Cyan("\t\t\t\t\t\t\t\t|*****************************************|")
	fmt.Println("")
}

func printPrompts() {
	fmt.Println("")
	color.Cyan("\t\t\t\t\t\t\t\t|*********************************************************|")
	color.Green("\t\t\t\t\t\t\t\t| Доступные команды: ")
	fmt.Println("\t\t\t\t\t\t\t\t| 1. <Получатели> (отображает имена всех доступных получателей)		")
	fmt.Println("\t\t\t\t\t\t\t\t| 2. <Файлы> (отображает названия всех файлов, доступных для загрузки)		")
	fmt.Println("\t\t\t\t\t\t\t\t| 3. <Отправить> <имя_получателя> <имя_файла>	(шифрует и загружает выбранный файл на сервер)	")
	fmt.Println("\t\t\t\t\t\t\t\t| 4. <Скачать> <имя_файла>	(скачивает и дешифрует файл, сохраняя его в папке decrypted)	")
	fmt.Println("\t\t\t\t\t\t\t\t| 5. <Помощь> (выводит на экран список доступных команд)	")
	fmt.Println("\t\t\t\t\t\t\t\t| 6. <Выйти> (завершает работу приложения)		")
	color.Cyan("\t\t\t\t\t\t\t\t|*********************************************************|")
	fmt.Println("")

}

func HandleClient(algorithm *string) {
	s := bufio.NewScanner(os.Stdin)
	n := bufio.NewScanner(os.Stdin)

	fmt.Print("Пожалуйста, введите ваш никнейм (без пробелов или иных разделителей): ")
	n.Scan()
	userName := n.Text()
	nameArr := strings.Split(userName, " ")

	if len(userName) < 2 || len(nameArr) > 1 {
		color.Red("Ваш никнейм должен быть длиннее 2 символов и не содержать разделителей. Пожалуйста, попробуйте снова: ")
		n.Scan()
		userName = n.Text()
		nameArr = strings.Split(userName, " ")
		if len(userName) < 2 || len(nameArr) > 1 {
			userName = nameArr[0]
		}
	}

	CurrentUserName = userName

	switch *algorithm {
	case "NTRUENCRYPT":
		CreateNewNTRUEncryptClient(userName)
	case "BLOWFISH":
		CreateNewBlowfishClient(userName)
	}

	RefreshUsers(CurrentUserName)
	RefreshSampleFiles(SamplesPath)

	fmt.Println("")
	color.Green(fmt.Sprintf("Добро пожаловать, %s. По умолчанию выбран алгоритм шифрования %s", userName, *algorithm))
	fmt.Println("")

	printPrompts()

	fmt.Printf("ftp>> ")
	for i := 0; s.Scan(); i++ {
		if i == 0 {
			fmt.Printf("ftp>> ")
		}
		cmd := s.Text()
		cmdArr := strings.Split(cmd, " ")
		switch strings.ToLower(cmdArr[0]) {
		case "отправить", "upload":
			if len(cmdArr) != 3 {
				color.Red("Пожалуйста, введите имя файла из списка. Получить список файлов, доступных для загрузки, можно получить с помощью команды <Файлы>")
				continue
			}

			if !slices.Contains(Users, cmdArr[1]) {
				color.Red("Ошибка при выборе получателя")
				break
			}

			if !slices.Contains(Samples, cmdArr[2]) {
				color.Red("Ошибка при выборе файла")
				break
			}

			switch *algorithm {
			case "NTRUENCRYPT":
				DirectoryNtrue.Name = UserNTRUE.Name
				UserNTRUE.ReceiverName = cmdArr[1]
				UploadFileNTRUEncrypt(cmdArr[1], cmdArr[2])
			case "BLOWFISH":
				DirectoryBlowfish.Name = UserBLOWFISH.Name
				UserBLOWFISH.ReceiverName = cmdArr[1]
				UploadFileBlowfish(cmdArr[1], cmdArr[2])
			}

			RefreshUsers(CurrentUserName)
			RefreshFiles(algorithm)
		case "получатели", "Users":
			if len(cmdArr) != 1 {
				color.Red("Пожалуйста, проверьте правильность введенной команды")
				continue
			}

			refreshedUsers, _ := RefreshUsers(CurrentUserName)

			if len(refreshedUsers) == 0 {
				color.Yellow("Получатели не найдены")
			}

			for _, v := range refreshedUsers {
				color.Cyan(fmt.Sprintf("-> %s", v))
			}
			RefreshUsers(CurrentUserName)
			RefreshFiles(algorithm)

		case "отправители":
			if len(cmdArr) != 1 {
				color.Red("Пожалуйста, проверьте правильность введенной команды")
				continue
			}

			_, refreshedSenders := RefreshUsers(CurrentUserName)

			if len(refreshedSenders) == 0 {
				color.Yellow("Получатели не найдены")
			}

			for _, v := range refreshedSenders {
				color.Cyan(fmt.Sprintf("-> %s", v))
			}
			RefreshUsers(CurrentUserName)
			RefreshFiles(algorithm)

		case "файлы", "files":
			if len(cmdArr) != 1 {
				color.Red("Пожалуйста, проверьте правильность введенной команды")
				continue
			}

			if DirectoryNtrue.Name == "" || DirectoryBlowfish.Name == "" {
				RefreshSampleFiles(SamplesPath)
				if len(Samples) == 0 {
					color.Yellow("Файлы отсутствуют")
					continue
				}
				for _, v := range Samples {
					color.Cyan(fmt.Sprintf("-> %s", v))
				}
				continue
			}

			refreshedFiles := RefreshFiles(algorithm)

			if len(refreshedFiles) == 0 {
				color.Yellow("Файлы отсутствуют")
				continue
			}

			for _, v := range refreshedFiles {
				color.Cyan(fmt.Sprintf("-> %s", v))
			}
			RefreshUsers(CurrentUserName)
			RefreshFiles(algorithm)
		case "скачать", "download":

			if len(cmdArr) != 3 {
				color.Red("Пожалуйста, проверьте правильность введенной команды")
				continue
			}

			if !slices.Contains(Directories, cmdArr[1]) {
				color.Red("Ошибка при выборе отправителя")
				break
			}

			switch *algorithm {
			case "NTRUENCRYPT":
				DirectoryNtrue.Name = cmdArr[1]
			case "BLOWFISH":
				DirectoryBlowfish.Name = cmdArr[1]
			}

			RefreshUsers(CurrentUserName)
			RefreshFiles(algorithm)

			if !slices.Contains(Files, cmdArr[2]) {
				color.Red("Ошибка при выборе файла")
				break
			}

			switch *algorithm {
			case "NTRUENCRYPT":
				DownloadFileNTRUEncrypt(cmdArr[2])
			case "BLOWFISH":
				DownloadFileBlowfish(cmdArr[2])
			}

			RefreshUsers(CurrentUserName)
			RefreshFiles(algorithm)

		case "выйти", "exit", "close":
			err := removeClients(UsersPath)
			if err != nil {
				log.Println(err)
			}
			err = removeFiles(EncFilesPath)
			if err != nil {
				log.Println(err)
			}
			err = removeFiles(ConstantsPath)
			if err != nil {
				log.Println(err)
			}
			return
		case "помощь":
			printPrompts()
		default:
			color.Red("Команда не опознана. Пожалуйста, проверьте правильность написания или воспользуйтесь справкой с помощью команды <Помощь>")
		}

		fmt.Printf("ftp>> ")

	}

}

func main() {
	algorithm := flag.String("Алгоритм", "BLOWFISH", "Алгоритм шифрования по умолчанию")
	flag.Parse()

	printTitle()
	HandleClient(algorithm)
}

func removeClients(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}

	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}

func removeFiles(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}
