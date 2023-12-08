package main

import (
	"bytes"
	"github.com/schollz/progressbar/v3"
	"io"
	"kursach/pkg/blowfish"
	"kursach/pkg/ntru"
	"log"
	"os"
	"path/filepath"
	"time"
)

var progressBar *progressbar.ProgressBar

func DecryptBlowFish(file *os.File, nameOfFile string, key []byte, bf *blowfish.Blowfish) error {
	var buffer bytes.Buffer

	out, err := os.OpenFile(filepath.Join(DecFilesPath, nameOfFile), os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Println(err)
		return err
	}
	defer out.Close()

	_, err = io.Copy(&buffer, file)
	if err != nil {
		log.Println(err)
		return err
	}
	data := buffer.Bytes()

	decContent := bf.Decrypt(data, progressBar)

	d := bytes.NewReader(decContent)

	_, err = io.Copy(out, d)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func EncryptBlowfish(nameOfFile string, key []byte, bf *blowfish.Blowfish) error {
	var buffer bytes.Buffer

	file, err := os.Open(filepath.Join(SamplesPath, nameOfFile))
	if err != nil {
		log.Println(err)
		return err
	}
	defer file.Close()

	err = os.Mkdir(filepath.Join(EncFilesPath, UserBLOWFISH.Name), 0705)
	if err != nil {
		log.Println(err)
		return err
	}

	out, err := os.OpenFile(filepath.Join(EncFilesPath, UserBLOWFISH.Name, nameOfFile), os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Println(err)
		return err
	}
	defer out.Close()

	_, err = io.Copy(&buffer, file)
	if err != nil {
		log.Println(err)
		return err
	}

	data := buffer.Bytes()

	encContent := bf.Encrypt(data, progressBar)

	r := bytes.NewReader(encContent)

	_, err = io.Copy(out, r)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func EncryptNtrue(nameOfFile string, publicKey *ntru.PublicKey, partSize int64) error {
	var buffer bytes.Buffer
	in, err := os.Open(filepath.Join(SamplesPath, nameOfFile))
	if err != nil {
		log.Println(err)
		return nil
	}
	defer in.Close()

	err = os.Mkdir(filepath.Join(EncFilesPath, UserNTRUE.Name), 0705)
	if err != nil {
		log.Println(err)
		return err
	}

	info, err := in.Stat()
	if err != nil {
		log.Println(err)
		return nil
	}
	fileSize := info.Size()

	parts := fileSize / partSize
	remainder := fileSize % partSize

	out, err := os.OpenFile(filepath.Join(EncFilesPath, UserNTRUE.Name, nameOfFile), os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer out.Close()

	progressBar = progressbar.Default(100)
	for i := int64(0); i < parts; i++ {
		buffer.Reset()
		_, err := io.CopyN(&buffer, in, partSize)
		if err != nil {
			log.Println(err)
			return nil
		}

		data := buffer.Bytes()

		encryptedContent, err := ntru.Encrypt(Reader, publicKey, data)
		if err != nil {
			log.Println(err)
			return nil
		}

		r := bytes.NewReader(encryptedContent)

		_, err = io.Copy(out, r)
		if err != nil {
			log.Println(err)
			return nil
		}

		progressBar.Set(int(float64(i+1) / (float64(parts) + float64(2)) * 100))
		time.Sleep(10 * time.Millisecond)
	}

	if remainder > 0 {
		buffer.Reset()
		_, err = io.CopyN(&buffer, in, remainder)
		if err != nil {
			return err
		}

		data := buffer.Bytes()

		encContent, err := ntru.Encrypt(Reader, publicKey, data)
		if err != nil {
			log.Println(err)
			return err
		}

		r := bytes.NewReader(encContent)

		_, err = io.Copy(out, r)
		if err != nil {
			log.Println(err)
			return nil
		}
	}
	progressBar.Set(100)

	return nil
}

func DecryptNtrue(file *os.File, nameOfFile string, privateKey *ntru.PrivateKey, partSize int64) error {
	fileInfo, err := file.Stat()
	if err != nil {
		log.Println(err)
		return err
	}
	fileSize := fileInfo.Size()

	parts := fileSize / partSize
	remainder := fileSize % partSize

	out, err := os.OpenFile(filepath.Join(DecFilesPath, nameOfFile), os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Println(err)
		return err
	}
	defer out.Close()

	var buff bytes.Buffer

	progressBar = progressbar.Default(100)
	for i := int64(0); i < parts; i++ {
		buff.Reset()
		_, err = io.CopyN(&buff, file, partSize)
		if err != nil {
			return err
		}

		data := buff.Bytes()

		decContent, err := ntru.Decrypt(privateKey, data)
		if err != nil {
			log.Println(err)
			return err
		}

		d := bytes.NewReader(decContent)

		_, err = io.Copy(out, d)
		if err != nil {
			log.Println(err)
			return nil
		}

		progressBar.Set(int(float64(i+1) / (float64(parts) + float64(2)) * 100))
		time.Sleep(10 * time.Millisecond)

	}

	if remainder > 0 {
		buff.Reset()
		_, err = io.CopyN(&buff, file, remainder)
		if err != nil {
			return err
		}

		data := buff.Bytes()

		decContent, err := ntru.Decrypt(privateKey, data)
		if err != nil {
			log.Println(err)
			return err
		}

		d := bytes.NewReader(decContent)

		_, err = io.Copy(out, d)
		if err != nil {
			log.Println(err)
			return nil
		}
	}
	progressBar.Set(100)

	return nil
}
