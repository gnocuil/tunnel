CC     := gcc
CFLAGS := -O2
TARGET := manage
OBJS   := main.o manage.o

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@
	
clean :
	rm -f $(TARGET)
	rm -f *.o
