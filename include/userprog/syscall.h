#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#endif /* userprog/syscall.h */
void check_address(void *addr);
void halt(void);
void exit(int status);