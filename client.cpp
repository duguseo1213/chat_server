#include <iostream>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

SSL_CTX* init_ssl_context() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// 서버로부터 수신 메시지 처리
void receive_messages(SSL* ssl) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));

        if (bytes_received <= 0) {
            std::cout << "Disconnected from server.\n";
            break;
        }

        std::cout << "Server: " << buffer << "\n";
    }
}

int main() {
    // SSL 초기화
    SSL_CTX* ctx = init_ssl_context();

    // 서버에 연결할 소켓 생성
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        std::cerr << "Failed to create socket.\n";
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // 서버 연결
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        std::cerr << "Connection failed.\n";
        return -1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // SSL 연결
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sock);
        SSL_CTX_free(ctx);
        return -1;
    }

    std::cout << "Connected to server using SSL/TLS.\n";

    // 닉네임 설정
    std::string nickname;
    std::cout << "Enter your nickname: ";
    std::getline(std::cin, nickname);

    // 메시지 수신 스레드 시작
    std::thread(receive_messages, ssl).detach();

    // 사용자 입력 및 메시지 전송
    std::string message;
    while (true) {
        std::cout << "You: ";
        std::getline(std::cin, message);

        if (message == "/quit") { // 종료 명령어
            break;
        }

        // 닉네임과 메시지 결합
        std::string full_message = nickname + ": " + message;

        if (SSL_write(ssl, full_message.c_str(), full_message.size()) <= 0) {
            std::cerr << "Failed to send message.\n";
            break;
        }
    }

    // 종료 처리
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
