CC     := g++
CFLAGS := -O2
TARGET := manage
OBJS   := main.o manage.o

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(CFLAGS)

%.o: %.cpp
	$(CC) -c -o $@ $<  $(CFLAGS)
	
clean :
	rm -f $(TARGET)
	rm -f *.o
