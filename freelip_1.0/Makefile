.IGNORE:

lippar.h: liptimer.c lip.c lip.h
	echo "" > lippar.h
	cc -DALPHA -O4 lip.c -c
	cc -DALPHA -O4 liptimer.c -c
	cc -DALPHA lip.o liptimer.o -lm -o liptimer
	echo "running timer program"
	./liptimer

lip.o: lippar.h lip.c lip.h
	cc -DALPHA -O4 lip.c -c

.c: lip.o lippar.h lip.h
	cc -DALPHA -O4 $< lip.o -lm -o $@

clean:
	rm -f *.o
