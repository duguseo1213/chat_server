#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>


int main() {
    int socket_desc;
    struct sockaddr_in server;
    char *message, server_reply[2000]; // 버퍼를 통해 서버 응답 저장
    int recv_size;

    // 소켓 생성
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        printf("Could not create socket\n");
        return 1;
    }

    // 서버 정보 설정
    server.sin_addr.s_addr = inet_addr("93.184.216.34"); // example.com
    server.sin_family = AF_INET;
    server.sin_port = htons(80);

    // 서버에 연결
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
        puts("connect error");
        return 1;
    }

    puts("Connected\n");

    // 요청 메시지
    message = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    // 서버에 메시지 전송
    if (send(socket_desc, message, strlen(message), 0) < 0) {
        puts("Send failed");
        return 1;
    }

    puts("Data Sent\n");

    // 서버로부터 응답 받기
    if ((recv_size = recv(socket_desc, server_reply, sizeof(server_reply) - 1, 0)) < 0) {
        puts("recv failed");
    } else {
        // 응답 출력
        server_reply[recv_size] = '\0'; // null-terminate the received data
        printf("Server Reply:\n%s\n", server_reply);
    }

    // 소켓 닫기
    close(socket_desc);

    return 0;
}
