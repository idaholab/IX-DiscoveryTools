package utils

import (
	"bufio"
	"log"
	"os"
	"regexp"
)

//ScanFile returns the contents of a file as a []string
func ScanFile(f *os.File) []string {
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	var text []string

	for scanner.Scan() {
		text = append(text, scanner.Text())
	}

	return text
}

// RemoveParenthesis removes leading and trailing parenthesis
// from a string
func RemoveParenthesis(s string) string {
	re1, err := regexp.Compile(`["("]`)
	if err != nil {
		log.Println(err)
	}
	re2, err := regexp.Compile(`[")"]`)
	if err != nil {
		log.Println(err)
	}

	str1 := re1.ReplaceAllString(s, "")
	str2 := re2.ReplaceAllString(str1, "")

	return str2
}
