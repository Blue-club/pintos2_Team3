#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);


void
timer_init (void) {

	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;
	/* CW: counter 0, LSB then MSB, mode 2, binary. */
	/* 0번 카운터가 시계 방향으로 동작하며, 카운터 값은 LSB부터 MSB로 표현되고, 카운터 모드는 2이며, 이진 형태로 표현된다는 것을 의미합니다.*/

	/* CW는 ClockWise(시계방향)으로 카운터가 시계방향으로 동작한다.
	   LSB는 (가장 낮은 자리의 비트), MSB는 (가장 높은 자리의 비트)를 의미한다.
	   mode2 는 카운터가 특정 값을 설정하고, 그 값을 카운트 다운하다가 0에 도달하면 재설정한다. */
	outb (0x43, 0x34);    
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
}

/* loops_per_tick값을 보정하여 정확한 시간 지연을 구현하기 위한 작업을 수행 */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	/*intr_get_level이 INTR_ON(인터럽트 활성화 상태)라면 실행*/
	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	/* loops_per_tick값을 timer tick보다 작은 가장 큰 2의 거듭제곱 값으로 근사화한다. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	/*  loops_per_tick 값을 계산하고, 이를 이용하여 초당 루프 수를 출력하는 작업을 수행한다. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
/*  OS가 부팅된 이후 경과한 타이머 틱의 수를 반환합니다. */
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();
	/*ticks는 타이머 틱의 수를 나타내는 전역 변수*/
	int64_t t = ticks;
	/*intr_set_level함수를 호출하여 이전의 인터럽트 레벨을 복원*/
	intr_set_level (old_level);
	barrier ();
	return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */

/* then 변수를 받아 현재까지 경과한 timer tick 수에서 then만큼 뺀 값을 return*/
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}
 
/* Suspends execution for approximately TICKS timer ticks. */
void
timer_sleep (int64_t ticks) {
	int64_t start = timer_ticks ();

	ASSERT (intr_get_level () == INTR_ON);
	// while (timer_elapsed (start) < ticks)
	// 	/*현재 실행중인 스레드가 CPU를 앙보하고 다른 스레드에게 실행기회를 주는 함수*/
	// 	thread_yield ();

	/* 경과한 타이머 틱의 수가 ticks보다 작은 경우, 
	thread_sleep(start + ticks) 함수를 호출하여 현재 스레드를 일시 중단시킵니다. */
	// if(timer_elapsed (start) < ticks)
	thread_sleep(start + ticks);
}

/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* 이 함수는 타이머 인터럽트가 발생하면 타이머 틱 카운트를 증가시키고 스레드 관련 작업을 처리하는 역할을 수행합니다.
이를 통해 정확한 시간 기반의 스레드 스케줄링이 가능해집니다.*/
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	ticks++;
	thread_tick ();

	/*next_tick_to_awake와 비교하여 깨워야 할 스레드가 sleep_list에있을때만 깨운다.*/
	if(get_next_tick_to_awake()<=ticks){
		thread_awake(ticks);
	}
}

/* LOOPS 반복이 한 개의 타이머 틱 이상을 기다려야 하는지 여부를 판단합니다. */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks;
	/*현재 타이머 틱의 수가 start와 같아질 때까지 기다립니다. 이를 통해 한 개의 타이머 틱이 지날 때까지 대기합니다. */
	while (ticks == start)
	/* 코드 실행순서 제어*/
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	/*LOOPS 반복을 실행합니다. 이 함수는 지정된 반복 횟수만큼의 작업을 수행하는데, 일정한 시간 지연을 발생시킵니다.*/
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	/* start와 ticks를 비교하여 타이머 틱 카운트가 변경되었는지 확인합니다. 
	만약 변경되었다면, LOOPS 반복이 너무 오래 실행되어 기다렸다는 의미이므로 true를 반환합니다. 그렇지 않으면 false를 반환합니다.*/
	barrier ();
	return start != ticks;
}

/* 이 함수를 사용하면 지정된 반복 횟수만큼의 작업을 수행하면서 실행을 지연시킬 수 있습니다. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
/* 주어진 시간(num/denom 초) 동안 실행을 일시 중단합니다.*/
static void
real_time_sleep (int64_t num, int32_t denom) {
	int64_t ticks = num * TIMER_FREQ / denom;

	/*현재 인터럽트 상태가 INTR_ON인지 확인합니다. 인터럽트가 활성화된 상태에서 실행을 일시 중단해야 정확한 동작을 보장할 수 있습니다.*/
	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* 최소한 한 개의 완전한 타이머 틱을 기다려야 할 때는 timer_sleep() 함수를 사용하여 실행을 일시 중단합니다. 
		이 함수는 CPU를 다른 프로세스에 양보하여 대기하는 동안 다른 작업이 실행될 수 있도록 합니다.*/
		timer_sleep (ticks);
	} else {
		/* 그렇지 않은 경우, 즉, 하위 틱(tick) 정확도가 필요한 경우에는 busy_wait() 함수를 사용하여 더 정확한 지연을 발생시킵니다. 
		이를 위해 분자(num)와 분모(denom)를 1000으로 나누어 오버플로우 가능성을 피합니다.*/
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
	/* timer_sleep() 함수는 대기 중에 CPU를 양보하여 다른 프로세스에게 실행 기회를 주는 반면,
	busy_wait() 함수는 더 정확한 하위 틱(tick) 단위의 지연을 발생시킵니다.*/
}
