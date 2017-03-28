void handlPwd(char *w);
void custFnc(char *w);
void getFile(int fd, int sfd);
void putFile(int fd, int sfd);

int main()
{
    int sockfd, numbytes;
    //char buf[MAXDATASIZE];
    char sendbuf[MAXDATASIZE];
    struct hostent *he;
    struct sockaddr_in their_addr;
    struct addrinfo *aip;
    int game = false;
    
    if((he=gethostbyname(getHostName())) == NULL)
    {
        perror("gethostname");
        exit(1);
    }
    
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        exit(1);
    }

    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(PORT);
    their_addr.sin_addr = *((struct in_addr *) he->h_addr);
    memset(&(their_addr.sin_zero), '\0', 8);

    if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("connect");
        exit(1);
    }
    printf("Connection has been established with server.\n");
    char *buf;
    buf = (char*)calloc(512, sizeof(char));
    numbytes = recv(sockfd, buf, 512, 0);
    printf("Server: %s \n", buf);		
    while(1)
    {
        fgets(sendbuf, MAXDATASIZE, stdin);
        numbytes = sizeof(sendbuf);
        sendbuf[numbytes] = '\0';
        if( strncmp(sendbuf, "bye", 3) == 0 || strncmp(sendbuf, "quit", 4) == 0)
        {
            printf("Good Bye\n");
            break;
        }
        else
        {
            if((numbytes = send(sockfd, sendbuf, sizeof(sendbuf), 0)) == -1)
            {
                perror("send");
                close(sockfd);
                exit(1);
            }

            sendbuf[numbytes] = '\0';
            printf("Send: %s\n", sendbuf);

            if((numbytes = recv(sockfd, buf, 512, 0)) == -1)
            {
                perror("recv");
                exit(1);
            }
	    
            buf[numbytes] = '\0';
       	     
            printf("Received: %s\n", buf);
	        memset(buf, 0, sizeof(buf));
        }
    }

    close(sockfd);

    exit(0);
}

void handPwd(char *w)
{
    FILE *fp;

    fp = popen("pwd", "r");
    while(fgets(w, 512, fp) != NULL)
        printf("%s\n", w);
    pclose(fp);
}

void getFile(int fd, int sfd)
{
     
}
