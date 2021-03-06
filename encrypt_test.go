package main

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func TestEncrypt(t *testing.T) {
	fmt.Printf("\n--------------------------- TestEncrypt ---------------------------\n")
	t.Run(fmt.Sprintf("should not encrypt when length <= %d", aes.BlockSize), func(st *testing.T) {
		expected := "abcde"
		if expected != string(Encrypt([]byte(expected))) {
			st.Fail()
		}
	})
	t.Run(fmt.Sprintf("should not encrypt the remaining part when length%%%d != 0", aes.BlockSize), func(st *testing.T) {
		expected := "12345678901234567890"
		if expected[aes.BlockSize:] != string(Encrypt([]byte(expected)))[aes.BlockSize:] {
			st.Fail()
		}
	})
	t.Run("should not equal to non-encrypted string", func(st *testing.T) {
		expected := "1234567890123456"
		actualBytes := Encrypt([]byte(expected))
		actualEncrypt := string(actualBytes)
		if expected == actualEncrypt {
			st.Fail()
		}
	})
}

func TestEencryptAndDecrypt(t *testing.T) {
	fmt.Printf("\n--------------------------- TestEencryptAndDecrypt ---------------------------\n")
	expected1 := "abcdefghijklmnopqrst"
	actual1 := string(Decrypt(Encrypt([]byte(expected1))))
	if expected1 != actual1 {
		t.Fatalf("Decrypt does not match Encrypt")
	}
	t.Run(fmt.Sprintf("length==%d", aes.BlockSize), func(st *testing.T) {
		expected := "1234567890123456"
		actualBytes := Encrypt([]byte(expected))
		actual := string(Decrypt(actualBytes))
		if expected != actual {
			st.Fail()
		}
	})
	t.Run("a json string", func(st *testing.T) {
		expected := "{\"a\":123456,\"b\":7890,\"c\":true,\"d\":\"2018-12-08T08:25:32.696Z\",\"e\":\"abcdefghijklmnopqrstuvwxyz\"}"
		if expected != string(Decrypt(Encrypt([]byte(expected)))) {
			st.Fail()
		}
	})
}

func getNormalRowData() string {
	normalRowData := "{\"ID\":\"6bc3b4e0-b842-4162-b045-f9a40f1f9bdd\",\"SheetID\":\"54252eb5-f7eb-4fe0-98e6-4e27359841e9\",\"BookID\":\"15ef179a-387e-470c-bee2-a2b30716c2c5\",\"Data\":\"eyIyMjFmYjdjOS0zMzkzLTRlZTctOTJkZS1mMWUzYTI5M2E0ZDMiOiJjZTYyZDI4NS00OTI4LTQ5ZmEtYTM0Mi0wNDJhZGFlOTBjMWYiLCIyMjFmYjdjOS0zNmYyLTQ4NmItOWIxZi1mMzE5NzBlMDA1NGIiOlsiNThiNGQ4MGYtZjYxMC00YmVmLWJjYzUtMzBmMjgyNzMyZmY3Il0sIjIyMWZiN2M5LTQ5MWYtNDk3OC1hYTRjLTY3NGZhYTliNGIzNSI6W3siZGF0YSI6eyIxMjAqMTgiOiI0OTgxZmYwMy05NzFlLTQzZTEtYjljOC0xNWFlZTAzNGYzYjhlNDI4NTc4OS1hNmI0LTQ0Y2ItODQ2NC00ZDE1MmQwMGI5NGEvYmxvYiIsIjE0MCoxNDAiOiI0OTgxZmYwMy05NzFlLTQzZTEtYjljOC0xNWFlZTAzNGYzYjhhYjAzODMxMy00MjQxLTRlNGItYWRlMS1iY2RkYjdlOWRiMjUvYmxvYiIsIjMwMCozMDAiOiI0OTgxZmYwMy05NzFlLTQzZTEtYjljOC0xNWFlZTAzNGYzYjg0ZTY0ODYxNy0xMDFiLTRlYjAtOGNmYy1lYmU1OWZiZjFmOWIvYmxvYiIsImlkIjoiNDk4MWZmMDMtOTcxZS00M2UxLWI5YzgtMTVhZWUwMzRmM2I4ODdlMGNjMzctMTc1Yy00Mjk4LWEzYzQtYjllMThlZTZhZWI3L+WbvueJhzEucG5nIn0sIm5hbWUiOiLlm77niYcxLnBuZyJ9LHsiZGF0YSI6eyIxMjAqMTgiOiI0OTgxZmYwMy05NzFlLTQzZTEtYjljOC0xNWFlZTAzNGYzYjgyOTRiMjUxYy0zNWE2LTRjMzctODI0NS04ZDc3N2I5OTMwYzUvYmxvYiIsIjE0MCoxNDAiOiI0OTgxZmYwMy05NzFlLTQzZTEtYjljOC0xNWFlZTAzNGYzYjgzMmI3NDcxZS05MjEyLTQ1ODMtYjNhNS0wNmEwODZhM2VlNzUvYmxvYiIsIjMwMCozMDAiOiI0OTgxZmYwMy05NzFlLTQzZTEtYjljOC0xNWFlZTAzNGYzYjg5ZTE3NDExZi00NmZkLTRlNzMtYjAyMC03ZjU5OTNjODZmMjkvYmxvYiIsImlkIjoiNDk4MWZmMDMtOTcxZS00M2UxLWI5YzgtMTVhZWUwMzRmM2I4OGVhMTA2ZjUtNGJlNC00OTljLWJiZWQtZjAyNDA5ZTU5OGQyL+WbvueJhzEucG5nIn0sIm5hbWUiOiLlm77niYcxLnBuZyJ9LHsiZGF0YSI6eyIxMjAqMTgiOiI0OTgxZmYwMy05NzFlLTQzZTEtYjljOC0xNWFlZTAzNGYzYjg1ODJjMmI2My0wNTUwLTRiZDQtYmMwMC0wNGI0ODY0YjZhNGMvYmxvYiIsIjE0MCoxNDAiOiI0OTgxZmYwMy05NzFlLTQzZTEtYjljOC0xNWFlZTAzNGYzYjhiMDM0MTQ0Zi0wN2NmLTQ0MWQtYjU2Mi0zZjVmYjFiYzA0MTYvYmxvYiIsIjMwMCozMDAiOiI0OTgxZmYwMy05NzFlLTQzZTEtYjljOC0xNWFlZTAzNGYzYjg0MTNmNWM1Zi1lN2ZlLTQyYzMtODhlMC0zZjMxZjVjMzNhZGUvYmxvYiIsImlkIjoiNDk4MWZmMDMtOTcxZS00M2UxLWI5YzgtMTVhZWUwMzRmM2I4NDc0YjlkMTEtYWI2Mi00YTJjLWJiNTgtMWE3MzlkOWMxYzEzL+WbvueJhzEucG5nIn0sIm5hbWUiOiLlm77niYcxLnBuZyJ9XSwiMjIxZmI3YzktNGQ3MC00MWE3LTg5MDUtYWVmMzU2Njg3Y2JiIjpbIjYzM2Y5YWE4LTExZTktNGZkMC05MWFhLTdkMGYzMTIxODczMyJdLCIyMjFmYjdjOS03MjMyLTRhOTAtYWM4Mi1jNGY0ZTEwYzU2YjYiOlsiMWViMDRmOWMtNjliMC00ZWFhLWFmOGItZTIyOWVjMDdmNGExIl0sIjIyMWZiN2M5LTdiYmMtNDM5MC1iYmMzLTNmOGNjY2UwMzQ4NiI6IjIwMTgtMTAtMjBUMTY6MjA6NTkuOTU0MDg0NyswODowMCIsIjIyMWZiN2M5LWM1YmMtNDAzNy1iZGVkLTJhMjA2Njk2ZjdjMCI6WyI2N2Q4ZTkwMS1mYjhiLTRjMTYtOGZkNy0xYzFlMDFlNzVhODAiXSwiNDBiZjUwMGEtNmEwZC00MjVlLWFjNmEtZTlhOTEwMDc4MjdmIjp7InJpY2hUZXh0U3RhdGUiOnsiYmxvY2tzIjpbeyJkYXRhIjp7fSwiZGVwdGgiOjAsImVudGl0eVJhbmdlcyI6W10sImlubGluZVN0eWxlUmFuZ2VzIjpbXSwia2V5IjoiNHJlM2QiLCJ0ZXh0Ijoic3RlcDoiLCJ0eXBlIjoidW5zdHlsZWQifSx7ImRhdGEiOnt9LCJkZXB0aCI6MCwiZW50aXR5UmFuZ2VzIjpbXSwiaW5saW5lU3R5bGVSYW5nZXMiOltdLCJrZXkiOiI4NXEzayIsInRleHQiOiIxLuWIm+W7uuS6huW+iOWkmuWIl++8jOS4i+mdouacieaoquWQkea7muWKqOadoSIsInR5cGUiOiJ1bnN0eWxlZCJ9LHsiZGF0YSI6e30sImRlcHRoIjowLCJlbnRpdHlSYW5nZXMiOltdLCJpbmxpbmVTdHlsZVJhbmdlcyI6W10sImtleSI6IjlyNWo1IiwidGV4dCI6IjIu56e75Yqo5YiX55qE5L2N572u77yM56e75Yqo5YiX55qE6Zi05b2x6Iul6L+b5YWl5LqG5Li76ZSuIiwidHlwZSI6InVuc3R5bGVkIn0seyJkYXRhIjp7fSwiZGVwdGgiOjAsImVudGl0eVJhbmdlcyI6W10sImlubGluZVN0eWxlUmFuZ2VzIjpbXSwia2V5IjoiN3BuZmEiLCJ0ZXh0IjoiMy7liJnkuIvpnaLnmoTmu5rliqjmnaHlnKjnvKnnn60iLCJ0eXBlIjoidW5zdHlsZWQifSx7ImRhdGEiOnt9LCJkZXB0aCI6MCwiZW50aXR5UmFuZ2VzIjpbXSwiaW5saW5lU3R5bGVSYW5nZXMiOltdLCJrZXkiOiI4ZmpnNCIsInRleHQiOiJleHBlY3Q6IiwidHlwZSI6InVuc3R5bGVkIn0seyJkYXRhIjp7fSwiZGVwdGgiOjAsImVudGl0eVJhbmdlcyI6W10sImlubGluZVN0eWxlUmFuZ2VzIjpbXSwia2V5IjoiN3A1NWgiLCJ0ZXh0Ijoi56e75Yqo5YiX55qE5L2N572u77yM5rua5Yqo5piv5LuO5Li76ZSu5ZCOIOeahOesrOS4gOS4quWIl+W8gOWniyIsInR5cGUiOiJ1bnN0eWxlZCJ9XSwiZW50aXR5TWFwIjp7fX0sInRleHQiOiJzdGVwOlxuMS7liJvlu7rkuoblvojlpJrliJfvvIzkuIvpnaLmnInmqKrlkJHmu5rliqjmnaFcbjIu56e75Yqo5YiX55qE5L2N572u77yM56e75Yqo5YiX55qE6Zi05b2x6Iul6L+b5YWl5LqG5Li76ZSuXG4zLuWImeS4i+mdoueahOa7muWKqOadoeWcqOe8qeefrVxuZXhwZWN0Olxu56e75Yqo5YiX55qE5L2N572u77yM5rua5Yqo5piv5LuO5Li76ZSu5ZCOIOeahOesrOS4gOS4quWIl+W8gOWniyJ9LCI0MGJmNTAwYS02YjU5LTRjNmYtYmI3Mi1hNjdjNTllNzI2MzciOnsidGV4dCI6IldoZW4gdGhlcmUgYXJlIG1vcmUgY29sdW1ucywgdGhlcmUgaXMgYSBob3Jpem9udGFsIHNjcm9sbCBiYXIgYmVsb3cuIFdoZW4gdGhlIHNoYWRvdyBvZiB0aGUgbW92aW5nIGNvbHVtbiBlbnRlcnMgdGhlIHByaW1hcnkga2V5LCB0aGUgc2Nyb2xsaW5nIHJhbmdlIGJlbG93ZCB3aWxsIGJlIHJlZHVjZWQuIiwicmljaFRleHRTdGF0ZSI6eyJibG9ja3MiOlt7ImtleSI6IjZ0NDNhIiwidGV4dCI6IldoZW4gdGhlcmUgYXJlIG1vcmUgY29sdW1ucywgdGhlcmUgaXMgYSBob3Jpem9udGFsIHNjcm9sbCBiYXIgYmVsb3cuIFdoZW4gdGhlIHNoYWRvdyBvZiB0aGUgbW92aW5nIGNvbHVtbiBlbnRlcnMgdGhlIHByaW1hcnkga2V5LCB0aGUgc2Nyb2xsaW5nIHJhbmdlIGJlbG93ZCB3aWxsIGJlIHJlZHVjZWQuIiwidHlwZSI6InVuc3R5bGVkIiwiZGVwdGgiOjAsImlubGluZVN0eWxlUmFuZ2VzIjpbXSwiZW50aXR5UmFuZ2VzIjpbXSwiZGF0YSI6e319XSwiZW50aXR5TWFwIjp7fX19LCI0MGJmNTAwYS05NmRiLTRlZjktODUzNi04ZjVjYWVlZTQwZTMiOjE5MDQsIjY3MTQyOTc3LTYzM2ItNDZiMy05N2M4LWNjZGEzZTM2Y2FiNCI6ImNlNjJkMjg1LTQ5MjgtNDlmYS1hMzQyLTA0MmFkYWU5MGMxZiIsIjY3MTQyOTc3LWE5Y2ItNGJhMi05MWUwLTg4ZDlkMjEyYWE0ZCI6IjIwMTgtMTItMDhUMTk6MzU6MDAuMjI4NzA1NCswODowMCIsImFkZC1jb21tZW50cy1hY3Rpb24tNDBiZjUwMGEtODQyNy00ODQ3LThkNjEtOGUyYjQ4N2MyZGRmIjowLCJpbmRleCI6MTEzNDUwLCIyMjFmYjdjOS0wZjA2LTRlOTYtYmZhNS1kNjcyMzM2MGQwNjAiOlsiYzRhZmY1NDktYzNmNC00NWQwLTg5MGQtNzEzOGQ5MDZiNTYxIl0sIm1ldGFkYXRhIjp7ImNvbW1lbnRDb3VudCI6MCwiY3JlYXRlZCI6IjIwMTgtMTAtMjBUMTY6MjA6NTkuOTU0MDg0NyswODowMCIsImNyZWF0ZWRCeSI6ImNlNjJkMjg1LTQ5MjgtNDlmYS1hMzQyLTA0MmFkYWU5MGMxZiIsIm1vZGlmaWVkIjoiMjAxOC0xMi0wOFQxOTozNTowMC4yMjg3MDU0KzA4OjAwIiwibW9kaWZpZWRCeSI6ImNlNjJkMjg1LTQ5MjgtNDlmYS1hMzQyLTA0MmFkYWU5MGMxZiJ9fQ==\",\"Timestamp\":\"2018-12-08T19:37:33.8803381+08:00\",\"ModifiedBy\":\"ce62d285-4928-49fa-a342-042adae90c1f\",\"CreatedTime\":\"2018-10-20T16:20:59.9540847+08:00\",\"CreatedBy\":\"ce62d285-4928-49fa-a342-042adae90c1f\"}"
	return normalRowData
}

func BenchmarkEncrypt(b *testing.B) {
	rowData := getNormalRowData()
	for i := 0; i < b.N; i++ {
		Encrypt([]byte(rowData))
	}
}

func BenchmarkCryptPair(b *testing.B) {
	rowData := getNormalRowData()
	for i := 0; i < b.N; i++ {
		Decrypt(Encrypt([]byte(rowData)))
	}
}

func BenchmarkEncryptBigData(b *testing.B) {
	size := 1 * 1024 * 1024 // 1MiB
	data := make([]byte, size)
	io.ReadFull(rand.Reader, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt([]byte(data))
	}
}

func BenchmarkEncryptFiles(b *testing.B) {
	f, err := ioutil.TempFile(os.TempDir(), "benchFile")
	if err != nil {
		b.Fatalf("can not create tempfile: %v", err)
	}
	fileName := f.Name()
	fileSize := 5 * 1024 * 1024 // 5MiB
	data := make([]byte, fileSize)
	io.ReadFull(rand.Reader, data)
	if n, err := f.Write(data); err != nil || n != fileSize {
		b.Fatalf("can not fill file with random data: %v", err)
	}
	f.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f, err := os.Open(fileName)
		if err != nil {
			b.Fatalf("open file error: %v", err)
		}
		content, err := ioutil.ReadAll(f)
		if err != nil {
			b.Fatalf("open but read file error: %v", err)
		}
		Encrypt(content)
		f.Close()
	}
}

func TestNewEncrypt(t *testing.T) {
	fmt.Printf("\n--------------------------- TestNewEncrypt ---------------------------\n")
	t.Run("should not equal to non-encrypted string", func(st *testing.T) {
		expected := "1234567890123456"
		actualBytes := NewEncrypt([]byte(expected))
		actualEncrypt := string(actualBytes)
		if expected == actualEncrypt {
			st.Fail()
		}
	})
}

func TestNewEncryptAndNewDecrypt(t *testing.T) {
	fmt.Printf("\n--------------------------- TestNewEncryptAndNewDecrypt ---------------------------\n")
	expected1 := "abcdefghijklmnopqrst"
	actual1 := string(NewDecrypt(NewEncrypt([]byte(expected1))))
	if expected1 != actual1 {
		t.Fatalf("Decrypt does not match Encrypt")
	}
	t.Run(fmt.Sprintf("length==%d", aes.BlockSize), func(st *testing.T) {
		expected := "1234567890123456"
		actualBytes := NewEncrypt([]byte(expected))
		actual := string(NewDecrypt(actualBytes))
		if expected != actual {
			st.Fail()
		}
	})
	t.Run("a json string", func(st *testing.T) {
		expected := "{\"a\":123456,\"b\":7890,\"c\":true,\"d\":\"2018-12-08T08:25:32.696Z\",\"e\":\"abcdefghijklmnopqrstuvwxyz\"}"
		if expected != string(NewDecrypt(NewEncrypt([]byte(expected)))) {
			st.Fail()
		}
	})
}

func BenchmarkNewEncrypt(b *testing.B) {
	rowData := getNormalRowData()
	for i := 0; i < b.N; i++ {
		NewEncrypt([]byte(rowData))
	}
}

func BenchmarkNewCryptPair(b *testing.B) {
	rowData := getNormalRowData()
	for i := 0; i < b.N; i++ {
		NewDecrypt(NewEncrypt([]byte(rowData)))
	}
}

func BenchmarkNewEncryptBigData(b *testing.B) {
	size := 1 * 1024 * 1024 // row data size: 1MiB
	data := make([]byte, size)
	io.ReadFull(rand.Reader, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewEncrypt([]byte(data))
	}
}

func BenchmarkNewEncryptFiles(b *testing.B) {
	fileSize := 5 * 1024 * 1024 // 5MiB
	f, err := ioutil.TempFile(os.TempDir(), "benchFile")
	if err != nil {
		b.Fatalf("can not create tempfile: %v", err)
	}
	fileName := f.Name()
	data := make([]byte, fileSize)
	io.ReadFull(rand.Reader, data)
	if n, err := f.Write(data); err != nil || n != fileSize {
		b.Fatalf("can not fill file with random data: %v", err)
	}
	f.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f, err := os.Open(fileName)
		if err != nil {
			b.Fatalf("open file error: %v", err)
		}
		content, err := ioutil.ReadAll(f)
		if err != nil {
			b.Fatalf("open but read file error: %v", err)
		}
		NewEncrypt(content)
		f.Close()
	}
}
