/* 
----SHELL----
Nota ->3,75/5

Falta fazer:
History e o Background
Melhorar tratamento de erro
*/



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h> 

// Protótipos das funções
char **receberEntrada(size_t *tamanho_atual, size_t *tamanho_total, FILE *batchFile);
void executarComandosSequen(char **comandos);
void *executarComando(void *arg);
void executarComandosParl(char **comandos);
void *executarComandoPipe(void *arg);
void duplicarComandos(char **comandos);
void executarComandosComRedirecionamento(char *comando);
int bool_flag = 1; // Variável global para bool_flag
char **ultima_string = NULL;

void sig_handler(int signo) {
    if (signo == SIGUSR1) {
        bool_flag = 0; 
    }
}


int main(int argc, char *argv[]) {
    signal(SIGUSR1, sig_handler);
    int sequencial = 1; // Flag para determinar execução sequencial por padrão
    char *batchFileName = NULL;
    int style = 0;
   
    FILE *batchFile = NULL;

    if (argc == 2) {
        batchFile = fopen(argv[1], "r");
        if (batchFile == NULL) {
            perror("Erro ao abrir o arquivo de lote");
            return 1;
        }
    }

    while (bool_flag) {
        if (sequencial) {
            printf("gsa3 seq> ");
        } else {
            printf("gsa3 par> ");
        }
        fflush(stdout);

        size_t tamanho_atual = 0;
        size_t tamanho_total = 128; // Tamanho inicial da entrada

        char **comandos = NULL;

        if (batchFile) {
            comandos = receberEntrada(&tamanho_atual, &tamanho_total, batchFile);
            if (feof(batchFile)) {
                break;
                bool_flag = 0;
            }
        } else {
            comandos = receberEntrada(&tamanho_atual, &tamanho_total, NULL);
        }
        if (feof(stdin)) {
            printf("Ctrl+D (EOF) detectado. Encerrando o programa.\n");
        break; // Sair do loop principal
        }

        if (comandos == NULL) {
            continue;
        }


        // Verificar se o comando é para mudar o estilo
        if (strstr(comandos[0], "style sequential") !=NULL) {
            sequencial = 1;
            free(comandos); // Liberar memória alocada para comandos
            continue;
        } else if (strstr(comandos[0], "style parallel") !=NULL) {
            sequencial = 0;
            free(comandos); // Liberar memória alocada para comandos
            continue;
        }
         if(batchFile){
            printf("comandos: ");
            for (int i = 0; comandos[i] != NULL; i++){
                printf(" %s ", comandos[i]);
            }
            printf("\n");
        }

        // Verificar se a entrada contém "exit"
        if (sequencial) {
            executarComandosSequen(comandos);
        } else if(!sequencial) {
            executarComandosParl(comandos);
        }else if (batchFile || !sequencial) {
            if (sequencial) {
                executarComandosSequen(comandos);
            } else {
                executarComandosParl(comandos);
            }
        }
     
        // Executar os comandos
        
        if (!bool_flag) {
            // Liberar a memória alocada dinamicamente para comandos
            for (int i = 0; comandos[i] != NULL; i++) {
                free(comandos[i]);
            }
            free(comandos);
            break; // Sair do loop principal
        }
        // Liberar a memória alocada dinamicamente para comandos
        for (int i = 0; comandos[i] != NULL; i++) {
            free(comandos[i]);
        }
        free(comandos);
    } // Fim do loop while
    if (batchFile) {
        fclose(batchFile);
    }

    return 0;
}

char **receberEntrada(size_t *tamanho_atual, size_t *tamanho_total, FILE *batchFile) {
    char **comandos = (char **)malloc(sizeof(char *) * (*tamanho_total));
    if (comandos == NULL) {
        perror("Erro na alocação de memória");
        exit(1);
    }

    char *entrada = (char *)malloc(*tamanho_total);
    if (entrada == NULL) {
        perror("Erro na alocação de memória");
        exit(1);
    }

    while (1) {
        int c;

        if (batchFile != NULL) {
            c = fgetc(batchFile);  // Ler comandos do arquivo de lote
        } else {
            c = fgetc(stdin);  // Ler comandos da entrada padrão (terminal)
        }

        if (c == EOF || c == '\n') {
            if (*tamanho_atual > 0) {
                entrada[*tamanho_atual] = '\0'; // Adicione um terminador nulo

                // Dividir a entrada em comandos usando strtok
                char *comando = strtok(entrada, ";");
                int indice = 0;

                while (comando != NULL) {
                    comandos[indice] = strdup(comando);
                    if (comandos[indice] == NULL) {
                        perror("Erro na alocação de memória");
                        exit(1);
                    }

                    indice++;
                    comando = strtok(NULL, ";");
                }

                comandos[indice] = NULL; // Marque o final do array de comandos
            } else {
                comandos = NULL; // Entrada vazia, definir comandos como nulo
            }

            break;
        }

        entrada[*tamanho_atual] = (char)c;
        (*tamanho_atual)++;

        // Verificar se a entrada excedeu o tamanho atual e realocar, se necessário
        if (*tamanho_atual >= *tamanho_total - 1) {
            *tamanho_total *= 2; // Dobre o tamanho
            char *nova_entrada = (char *)realloc(entrada, *tamanho_total);
            if (nova_entrada == NULL) {
                perror("Erro na realocação de memória");
                free(entrada);
                exit(1);
            }
            entrada = nova_entrada;
        }
    }

    return comandos;
}

void duplicarComandos(char **comandos){
    char **ultima_string = (char **)malloc(sizeof(char *) * (1000000));
    if (ultima_string == NULL) {
        perror("Erro na alocação de memória");
        exit(1);
    }
    int i = 0;
    while (comandos[i]!= NULL)
    {
        char *ultima_string = strdup(comandos[i]);
        i++;
    }
    
   
}

void *executarComando(void *arg) {
    char *comando = (char *)arg;
    // Execute o comando
    int status = system(comando);
    if (status != 0) {
        //fprintf(stderr, "Erro na execução do comando: %s\n", comando);
    }

    free(comando); // Libere a memória alocada para o comando
    return NULL;
}
/*
função para executar comandos de forma sequencial, cria um 
processo filho que possui varias threads e executa eleas de forma sequencial. 
*/

void *executarComandoPipe(void *arg) {
    char *comando = (char *)arg;

    //printf("Executando comando com pipe: %s\n", comando);

    char *comando1 = strtok(comando, "|");
    char *comando2 = strtok(NULL, "|");

    if (comando1 == NULL || comando2 == NULL) {
        fprintf(stderr, "Erro na divisão do comando para pipe: %s\n", comando);
        free(comando);
        return NULL;
    }

    FILE *pipe1 = popen(comando1, "r");
    if (pipe1 == NULL) {
        perror("Erro ao abrir o pipe para o primeiro comando");
        exit(1);
    }

    FILE *pipe2 = popen(comando2, "w");
    if (pipe2 == NULL) {
        perror("Erro ao abrir o pipe para o segundo comando");
        pclose(pipe1);
        exit(1);
    }

    char buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), pipe1)) > 0) {
        fwrite(buffer, 1, bytes_read, pipe2);
    }

    pclose(pipe1);
    pclose(pipe2);

    free(comando);
    return NULL;
}

void executarComandosSequen(char **comandos) {
    pid_t pid = fork();

    if (pid < 0) {
        fprintf(stderr, "Erro ao criar um processo filho\n");
        exit(1);
    } else if (pid == 0) {
        //printf("PID: %d\n", getpid());

        for (int i = 0; comandos[i] != NULL; i++) {
            pthread_t thread;
            char *comando = strdup(comandos[i]);

            if (comando == NULL) {
                perror("Erro na alocação de memória");
                exit(1);
            }

            if (strstr(comando, "exit") != NULL) {
                kill(getppid(), SIGUSR1);
                exit(0);
            }

            if (strstr(comando, "|") != NULL) {
                pthread_create(&thread, NULL, executarComandoPipe, comando);
            } else {
                if (pthread_create(&thread, NULL, executarComando, comando) != 0) {
                    fprintf(stderr, "Erro ao criar a thread para o comando: %s\n", comando);
                    exit(1);
                }
            }

            if (pthread_join(thread, NULL) != 0) {
                fprintf(stderr, "Erro ao aguardar a thread para o comando: %s\n", comando);
                exit(1);
            }
        }

        exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
    }
}
void executarComandosParl(char **comandos) {
    int num_comandos = 0;
    while (comandos[num_comandos] != NULL) {
        num_comandos++;
    }
    
    pid_t pids[num_comandos];
    int status;

    for (int i = 0; i < num_comandos; i++) {
        char *comando = comandos[i];

        if (strstr(comando, "exit") != NULL) {
            // Envie um sinal para o processo pai
            //kill(getppid(), SIGUSR1);
            exit(0);
        }

        if (strstr(comando, "|") != NULL) {
            // Este comando contém um pipe

            // Divida o comando em dois comandos separados
            char *comando1 = strtok(comando, "|");
            char *comando2 = strtok(NULL, "|");

            int pipe_fd[2];

            if (pipe(pipe_fd) == -1) {
                perror("Erro na criação do pipe");
                exit(1);
            }

            pid_t child_pid1 = fork();

            if (child_pid1 < 0) {
                perror("Erro ao criar o primeiro filho para o pipe");
                exit(1);
            }

            if (child_pid1 == 0) {
                // Este é o processo filho 1

                close(pipe_fd[0]); // Fecha a leitura do pipe

                // Redireciona a saída padrão para o pipe
                dup2(pipe_fd[1], STDOUT_FILENO);
                close(pipe_fd[1]);

                // Executa o primeiro comando no shell
                execl("/bin/sh", "/bin/sh", "-c", comando1, NULL);
                perror("Erro ao executar o primeiro comando do pipe");
                exit(1);
            }

            pid_t child_pid2 = fork();

            if (child_pid2 < 0) {
                perror("Erro ao criar o segundo filho para o pipe");
                exit(1);
            }

            if (child_pid2 == 0) {
                // Este é o processo filho 2

                close(pipe_fd[1]); // Fecha a escrita do pipe

                // Redireciona a entrada padrão para o pipe
                dup2(pipe_fd[0], STDIN_FILENO);
                close(pipe_fd[0]);

                // Executa o segundo comando no shell
                execl("/bin/sh", "/bin/sh", "-c", comando2, NULL);
                perror("Erro ao executar o segundo comando do pipe");
                exit(1);
            }

            // Este é o processo pai
            close(pipe_fd[0]);
            close(pipe_fd[1]);

            // Espere pelos dois filhos
            waitpid(child_pid1, NULL, 0);
            waitpid(child_pid2, NULL, 0);
        } else {
            // Este comando não contém um pipe
            pids[i] = fork();

            if (pids[i] < 0) {
                perror("Erro ao criar processo filho");
                exit(1);
            } else if (pids[i] == 0) {
                execl("/bin/sh", "/bin/sh", "-c", comando, NULL);
                perror("Erro ao executar o comando");
                exit(1);
            }
        }
    }

    // Este é o processo pai
    for (int i = 0; i < num_comandos; i++) {
        if (strstr(comandos[i], "|") == NULL) {
            waitpid(pids[i], &status, 0);
        }
    }
}

