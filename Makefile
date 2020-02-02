.PHONY: all clean

all: hallow.zip

clean:
	rm -vf hallow.zip hallow

hallow:
	go build -o hallow .

hallow.zip: hallow
	zip hallow.zip hallow
