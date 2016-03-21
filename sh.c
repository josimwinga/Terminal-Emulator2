#define BUFFER_SIZE 1024
#include "jobs.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>  



typedef void (*sighandler_t)(int);
/*function declarations*/
int set_redirection(int type);
char **parseline(char *cmdline, char **parsed_cmdline);
int cd_helper(char**cmd_args);
int rm_helper(char**cmd_args, int argc);
int ln_helper(char**cmd_args, int argc);
int evaluate(char **cmd_args, int argc);
int clear_buf(char *buf);
int __safe_write(int fd, const void *buf, size_t count);
int main(int argc, char** argv);
void sig_handler(int sig);
int __safe_signal(int sig, sighandler_t handler);
int fg_helper(pid_t pid);
int repl(int argc);
void reap();
void check_fg_signals(pid_t pid);

/*Global Variables*/
char *redir_info[3] = {NULL, NULL, NULL};
char *builtin_cmds[7] = {"cd", "ln", "rm", "exit", "jobs", "bg", "fg"};
int redir_in_okay = 1;
int redir_out_okay = 1;
int redir_true = 0;
pid_t fg_pid = 0;
pid_t shell_pid;
int bg_true = 0;
int jid = 1;
job_list_t *jobs_list;

/*
* parseline()
*
* - Description: parses the commandline, puts each argument 
*   into a new array and finds any redirection symbols. 
*
* -Arguments: the commandline: a pointer to an array of char *s, 
*	parsed commandline: a pointer to an empty aray of char *s where the 
*	arguments from the commandline will be placed
*
* - Return value: the parsed commandline
*/
char **parseline(char *cmdline, char **parsed_cmdline) {
	redir_in_okay = 1;
	redir_out_okay = 1;
	redir_true = 0; //denotes whether a redirection has been detected4
	bg_true = 0;
	int pos= 0;
	int redir_now = 0; //denotes whether a redirection is currently being found
	char *tok;
	char *redir_symb[3] = {"<", ">", ">>"};
	const char *delim = " \n	";

	//find each token in the commandline
	tok = strtok(cmdline, delim);

	while (tok!=NULL) {
		if(strcmp(tok, "&") == 0){
			bg_true = 1;
			parsed_cmdline[pos] = NULL;
			return parsed_cmdline;
		}
		if (strcmp(tok, redir_symb[0]) == 0) {
			//check for < symbols
			redir_now = set_redirection(0);
		} else if (strcmp(tok, redir_symb[1]) == 0) {
			//check for > symbols
			redir_now = set_redirection(1);
		} else if (strcmp(tok, redir_symb[2]) == 0) {
			redir_now = set_redirection(2);
		} else if (redir_now) {
			redir_info[redir_now] = tok;
			redir_now = 0;
		} else {
			//place all non-redir symbols into a new array of arguments
			parsed_cmdline[pos] = tok;
			pos++;
		}
		tok = strtok(NULL, delim);
	}
	parsed_cmdline[pos] = NULL;
	return parsed_cmdline;
}

/*
* set_redirection()
*
* - Description: checks if a redirection symbol has already been
*	found in the command line and sets the redirecion type, input
*	filename, and output filename.
*
* -Arguments: a char * the -input file and an int -the type of redirection
*				0 = > and 1 = << or <
*
* - Return value: an integer; 1 if a redirection is taking place, 0 if not
*/
int set_redirection(int type) {
	if(type == 0) {
		if(redir_in_okay) {
			redir_in_okay = 0;
		}else {
			perror("ERROR: multiple redirection symbols");
			return 0;
		}
	} else {
		if(redir_out_okay) {
			redir_out_okay = 0;
		} else {
			perror("ERROR: multiple redirection symbols");
			return 0;
		}
	} 
	return type;
}

/*
*  check_builtins()
*
* - Description: checks the first argument of the array of
*	commandline arguments to see if it is a builtin command and
*	calls the command helper if it is a builtin
*
* -Arguments: a char *array of the parsed commandline arguments
*
* - Return value: an int, 0 if the first argument is not a builtin 
*	function, 1 if the builtin command was executed successfully
*/
int check_builtins(char **cmd_args, int argc) {
	if (strcmp(cmd_args[0], builtin_cmds[0]) == 0) {
		return cd_helper(cmd_args);
	
	} else if (strcmp(cmd_args[0], builtin_cmds[1]) == 0) {
		return ln_helper(cmd_args, argc);
	
	} else if (strcmp(cmd_args[0], builtin_cmds[2]) == 0) {
		return rm_helper(cmd_args, argc);
	
	} else if (strcmp(cmd_args[0], builtin_cmds[3]) == 0) {
		exit(0);
	} else if (strcmp(cmd_args[0], builtin_cmds[4]) == 0) {
		jobs(jobs_list);
		return 1;
	} else if(strcmp(cmd_args[0], builtin_cmds[5]) == 0) {
		//put process in background
		char *char_jid = cmd_args[1];
		char_jid += 1;
		pid_t jid = atoi(char_jid);
		pid_t pid = get_job_pid(jobs_list, jid);
		kill(pid, SIGCONT);
		update_job_pid(jobs_list, pid, _STATE_RUNNING);
		if(fg_helper(pid)){
			fg_pid = 0;
		}
		return 1;
	} else if(strcmp(cmd_args[0], builtin_cmds[6]) == 0) {
		//put process in foreground
		char *char_jid = cmd_args[1];
		char_jid += 1;
		pid_t jid = atoi(char_jid);
		pid_t pid = get_job_pid(jobs_list, jid);
		pid_t pgid = getpgid(pid);
		kill(jid, SIGCONT);
		update_job_pid(jobs_list, pid, _STATE_RUNNING);
		fg_pid = pid;
		tcsetpgrp(STDIN_FILENO, pgid);
		//set signals to default
		__safe_signal(SIGINT, SIG_DFL);
		__safe_signal(SIGTSTP, SIG_DFL);
		__safe_signal(SIGQUIT, SIG_DFL);
		return 1;
	}
	return 0;
}

/*
* cd_helper()
*
* - Description: calls chdir() if the commandline was given 
*	enough arguments
*
* - Arguments: a char *array of the parsed commandline arguments
*
* - Return value: an int; 1 if the system call was executed corrctly
*/
int cd_helper(char**cmd_args) {
	if(cmd_args[1] == NULL) {
		__safe_write(STDERR_FILENO, "cd: syntax error", 16); 
	}else if (chdir(cmd_args[1]) == -1) {
		__safe_write(STDERR_FILENO, "cd: syntax error", 20);
	}
	return 1;
}

/*
* ln_helper()
*
* - Description: calls link() if the commandline was given 
*	enough arguments
*
* - Arguments: a char *array of the parsed commandline arguments
*
* - Return value: an int; 1 if the system call was executed corrctly
*/
int ln_helper(char**cmd_args, int argc) {
	if(argc < 1 || argc > 4) {
		perror("ln: 3 args expected");
	} else if(cmd_args[1] == NULL) {
		perror("ln: missing file operand");
	} else if(cmd_args[2] == NULL) {
		perror("ln: missing file destination");
	} else {
		if (link(cmd_args[1], cmd_args[2]) == -1) {
			perror("ln");
		}
	}
	return 1;
}

/*
* rm_helper()
*
* - Description: calls unlink() if the commandline was given 
*	enough arguments
*
* - Arguments: a char *array of the parsed commandline arguments
*
* - Return value: an int; 1 if the system call was executed corrctly
*/
int rm_helper(char**cmd_args, int argc) {
	if(argc < 1 || argc > 3) {
		perror("rm: 2 args expected");
	}else if(cmd_args[1] == NULL || cmd_args == '\0') {
		perror("rm: missing file operand");
	} else {
		if (unlink(cmd_args[1]) == -1) {
			perror("rm");
		}
	}
	return 1;
}

/*
* redirection_helper()
*
* - Description: redirects the standard input/output if the user has 
*	indicated redirection
*
* - Arguments: None
*
* - Return value: an int; 1 if the function executed correctly
*/
int redirection_helper() {
	int fd;
	if(redir_info[0]) {
		//input redir <
		fd = open(redir_info[0], O_RDWR, 0666);
		if(fd == -1){
			perror("<");
		}
		dup2(fd, STDIN_FILENO);
		if(close(fd) == -1){
			perror("< close");
		}	
	}
	if(redir_info[1]) {
		//outpt redir >
		fd = open(redir_info[1], O_RDWR | O_CREAT | O_TRUNC, 0666);
		if(fd == -1){
			perror(">");
		}
		dup2(STDOUT_FILENO, fd);
		if(close(fd) == -1){
			perror("> close");
		}
	}else if(redir_info[2]) {
		fd = open(redir_info[1], O_RDWR | O_APPEND | O_CREAT, 0666);
		if(fd == -1){
			perror(">>");
		}
		dup2(STDOUT_FILENO, fd);
		if(close(fd) == -1){
			perror(">> close");
		}
	}
	return 0;
}

/*
* evaluate()
*
* - Description: checks parsed commandline args for builtin functions,
*		if none are found, it calls fork() to create a new process and 
*		then calls execv() on the arguments from the commandline. sets
*		foreground/background processes
*
* - Arguments: a char *array of the parsed commandline arguments
*
* - Return value: an int, 0
*/
int evaluate(char **cmd_args, int argc) {
	pid_t pid, curr_jid, pgid;
	char new_job[200];
	// printf("fg_pid is :%d bg is: %d\n", (int)fg_pid, bg_true);

	//if nothing has been entered, return
	if(cmd_args[0] == NULL) {
		return 0;
	}
	//check for redirection
	if(redir_true){
		redirection_helper();
	}
	//check for built-in commands
	if(check_builtins(cmd_args, argc) == 1) {
		return 0;
	}
	
	pid = fork();
	//add job to list
	add_job(jobs_list, jid, pid, _STATE_RUNNING, cmd_args[0]);
	curr_jid = jid;
	jid++;

	if(pid == 0) {
		//pid was successful, handoff to child
		setpgid(pid, pid);
		//set signals to default
		__safe_signal(SIGINT, SIG_DFL);
		__safe_signal(SIGTSTP, SIG_DFL);
		__safe_signal(SIGQUIT, SIG_DFL);
		//if this is not a background process, tcetpgrp
		if(!bg_true) {
			pgid = getpgid(pid);
			fg_pid = getpid();
			tcsetpgrp(STDIN_FILENO, pgid);
		}
	
		if(execv(cmd_args[0], cmd_args) == -1) {
			perror("ERROR execv");
		}
		//if this returns, exit
		exit(0);
	}else if (pid < 0) {
		perror("ERROR");
	} else {
		if(bg_true) {
			sprintf(new_job, "[%d] (%d)\n", curr_jid, pid);
		    __safe_write(STDOUT_FILENO, new_job, strlen(new_job));	
		}else {
			fg_pid = pid;
			check_fg_signals(pid); 	
		} 		 
    }
	tcsetpgrp(STDIN_FILENO, getpgid(0));
	return 0;
}

/*
 * fg_helper
 *		Checks if the process change found by waitpid was the foreground process
 *
 * Arguments: pid_t the changed pid
 * Return value: 0 if the changed pid was not the foreground pid, 1 if it was
 */
int fg_helper(pid_t pid) {
	if(pid == fg_pid) {
		fg_pid = 0;
		return 1;
	}
	return 0;
}

/*
 * Clear buf
 *		Clears the input buffer
 *
 * Arguments: char *input buffer
 * Return value: 0 if no errors
 */
int clear_buf(char *buf) {
	int j;
	for(j = 0; j < 1024; j++) {
		buf[j] = '\0';
	}
	return 0;
}

int __safe_write(int fd, const void *buf, size_t count) {
	if (write(fd, buf, count) < 0) {
		perror("write");
	}
	return 0;
} 

int __safe_signal(int sig, sighandler_t handler) {
	if(signal(sig, handler) == SIG_ERR) {
			perror("Warning: signal error");
		}
	return 0;
}


/*
 * Check fg signals
 *		Calls waitpid and checks foreground process signals
 *
 * Arguments: pid_t pid, the pid of the foreground process
 * Return value: None
 */
void check_fg_signals(pid_t pid) {
	int status;
	pid_t pid_changed;
	int sig_num;
	char my_str[1024];

	while((pid_changed = waitpid(pid, &status, WUNTRACED)) > 0) {
		if(WIFEXITED(status)) {
			// child terminated normally
			tcsetpgrp(STDIN_FILENO, getpgid(0));
			remove_job_pid(jobs_list, pid_changed);
			fg_pid = 0;
		}
		if(WIFSIGNALED(status)) {
			//child process terminated by signal
			sig_num = WTERMSIG(status);
			sprintf(my_str, "[%d] (%d) terminated by signal %d\n", \
			get_job_jid(jobs_list, pid_changed), pid_changed, sig_num);
			__safe_write(STDOUT_FILENO, my_str, strlen(my_str));
			remove_job_pid(jobs_list, pid_changed);
			tcsetpgrp(STDIN_FILENO, getpgid(0));
			fg_pid = 0;
		}
		if(WIFSTOPPED(status)) {
			//stopped by return signal
			sig_num = WSTOPSIG(status);
			sprintf(my_str, "[%d] (%d) suspended by signal %d\n", \
				get_job_jid(jobs_list, pid_changed), pid_changed, sig_num);
			__safe_write(STDOUT_FILENO, my_str, strlen(my_str));
			update_job_pid(jobs_list, pid_changed, _STATE_STOPPED);
			tcsetpgrp(STDIN_FILENO, getpgid(0));
			fg_pid = 0;
			break;
		}
		if(WIFCONTINUED(status)) {
			//child resumed by SITCONT
			sprintf(my_str, "[%d] (%d) resumed\n", get_job_jid(jobs_list, pid_changed), pid_changed);
			__safe_write(STDOUT_FILENO, my_str, strlen(my_str));
			update_job_pid(jobs_list, pid_changed, _STATE_RUNNING);
		}
	}
}
/*
 * Reap Function
 *		Calls waitpid and checks process signals
 *
 * Arguments: None
 * Return value: None
 */
void reap() {
	int status;
	pid_t pid_changed;
	int exit_status;
	int sig_num;
	char my_str[1024];

	while((pid_changed = waitpid(-1, &status, WUNTRACED|WNOHANG|WCONTINUED)) > 0) {
		if(WIFEXITED(status)) {
			// child terminated normally
			exit_status = WEXITSTATUS(status);
		
			if(fg_helper(pid_changed)) {
				tcsetpgrp(STDIN_FILENO, getpgid(0));
			} else {
				sprintf(my_str, "[%d] (%d) terminated with exit status %d\n", 
				get_job_jid(jobs_list, pid_changed), pid_changed, exit_status);
				__safe_write(STDOUT_FILENO, my_str, strlen(my_str));
			}
			remove_job_pid(jobs_list, pid_changed);			
		}
		if(WIFSIGNALED(status)) {
			//child process terminated by signal
			sig_num = WTERMSIG(status);					
			
			if(fg_helper(pid_changed)) {
				tcsetpgrp(STDIN_FILENO, getpgid(0));
			}
			sprintf(my_str, "[%d] (%d) terminated by signal %d\n", \
				get_job_jid(jobs_list, pid_changed), pid_changed, sig_num);
			__safe_write(STDOUT_FILENO, my_str, strlen(my_str));
			remove_job_pid(jobs_list, pid_changed);
		}
		if(WIFSTOPPED(status)) {
			//stopped by return signal
			sig_num = WSTOPSIG(status);
			update_job_pid(jobs_list, pid_changed, _STATE_STOPPED);
			
			if(fg_helper(pid_changed)) {
				tcsetpgrp(STDIN_FILENO, getpgid(0));
			}
			sprintf(my_str, "[%d] (%d) suspended by signal %d\n", \
				get_job_jid(jobs_list, pid_changed), pid_changed, sig_num);
			__safe_write(STDOUT_FILENO, my_str, strlen(my_str));
		}
		if(WIFCONTINUED(status)) {
			//child resumed by SITCONT
			sprintf(my_str, "[%d] (%d) resumed\n", get_job_jid(jobs_list, pid_changed),\
			 	pid_changed);
			__safe_write(STDOUT_FILENO, my_str, strlen(my_str));
			update_job_pid(jobs_list, pid_changed, _STATE_RUNNING);
		}
	}
}


/*
 * Main function
 *
 * Arguments:
 *	- argc: the number of command line arguments - for this function 9
 *	- **argv: a pointer to the first element in the command line
 *            arguments array 
 * Return value: 0 if program exits correctly, 1 if there is an error
 */
int main(int argc, char** argv) {
	if(argc == 0 || !argv[0]) {
		return 1;
	}
	repl(argc);
	return 0;
}

/*
 * repl function: 
 *	infinitly loops until signaled to exit;
 *		-writes to user and reads the standard input
 *		-evaluates the read input
 *
 * Arguments:
 *	- argc: the number of command line arguments - for this function 9
 *	 
 * Return value: 0 if program exits correctly, 1 if there is an error
 */
int repl(int argc) {
	char *parsed_cmdline[1024];
	char buf[1024];
	char **line;
	ssize_t num_read;
	//jobs list
	jobs_list = init_job_list();
	shell_pid = getpid();
	//signals
	__safe_signal(SIGTTOU, SIG_IGN);
	__safe_signal(SIGINT, SIG_IGN);
	__safe_signal(SIGTSTP, SIG_IGN);
	__safe_signal(SIGQUIT, SIG_IGN);


	//infinite REPL loop
	while(1) {
		reap();

		#ifdef PROMPT
		//setup prompt for commandline
		const char *prompt = " $ ";
		char full_prompt[100];
		getcwd(full_prompt, 100);
		strcat(full_prompt, prompt);
		size_t len = strlen(full_prompt);
		//write prompt to the commandline
		__safe_write(STDOUT_FILENO, full_prompt, len);
		#endif 

		//read command line
		num_read = read(STDIN_FILENO, buf, 1024);
		if(num_read == 0) {
			exit(0);
		}else if(num_read == -1) {
			perror("READ ERROR");
		}
		//pase the command line
		line = parseline(buf, parsed_cmdline);
		//evaluate and execute the command line
		evaluate(line, argc);
		// check_signals(WUNTRACED|WUNTRACED);
		clear_buf(buf);
	}
	cleanup_job_list(jobs_list);
	return 0;
}
