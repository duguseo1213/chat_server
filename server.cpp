#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>
#include "httplib.h" // Cpp-HTTPLib 헤더 파일

std::vector<std::string> chat_log; // 채팅 로그 저장
std::mutex chat_mutex;

// SSL 초기화 함수
SSL_CTX* init_ssl_context() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 인증서와 키 파일 설정
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// 클라이언트 처리 함수
void handle_client(SSL* ssl) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));

        if (bytes_received <= 0) {
            std::cout << "Client disconnected.\n";
            SSL_free(ssl);
            break;
        }

        std::string message(buffer);
        std::cout << "Received: " << message << "\n";

        // 채팅 로그에 메시지 저장
        {
            std::lock_guard<std::mutex> lock(chat_mutex);
            chat_log.push_back(message);
        }

        // 클라이언트에게 에코
        SSL_write(ssl, message.c_str(), message.size());
    }
}

int main() {
    // TLS 초기화
    SSL_CTX* ctx = init_ssl_context();

    // TCP 서버 설정
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        std::cerr << "Failed to create socket.\n";
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(12345);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        std::cerr << "Binding failed.\n";
        return -1;
    }

    if (listen(server_socket, 5) == -1) {
        std::cerr << "Listening failed.\n";
        return -1;
    }

    std::cout << "Secure chat server running on port 12345.\n";

    // HTTP 서버 설정
    httplib::Server http_server;

    http_server.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        std::string response = R"(
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Chat Log</title>
                <style>
                    body {
                        font-family: 'Arial', sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #1e1e2f;
                        color: #ffffff;
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                    }
                    .header {
                        width: 100%;
                        background-color: #33334d;
                        padding: 20px;
                        text-align: center;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
                    }
                    .header h1 {
                        margin: 0;
                        font-size: 24px;
                    }
                    .chat-container {
                        width: 90%;
                        max-width: 800px;
                        height: 70vh;
                        background-color: #28293d;
                        border-radius: 10px;
                        overflow-y: auto;
                        padding: 20px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                        margin-top: 20px;
                    }
                    .chat-message {
                        margin: 10px 0;
                        padding: 15px;
                        border-radius: 8px;
                        background-color: #3c3c58;
                    }
                    .chat-message .sender {
                        font-weight: bold;
                        color: #f4b400;
                    }
                    .chat-message .time {
                        float: right;
                        font-size: 12px;
                        color: #cccccc;
                    }
                    .chat-message .content {
                        margin-top: 5px;
                        color: #ffffff;
                    }
                    .footer {
                        margin-top: 20px;
                        text-align: center;
                        font-size: 14px;
                        color: #bbbbbb;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Welcome to the Chat Room</h1>
                </div>
                <div class="chat-container">
        )";

        // 채팅 로그 읽기
        {
            std::lock_guard<std::mutex> lock(chat_mutex);
            for (const auto& msg : chat_log) {
                // 메시지에 이름과 시간을 추가
                response += R"(
                    <div class="chat-message">
                        <span class="sender">)" + msg.substr(0, msg.find(":")) + R"(</span>
                        <span class="time">)" +  R"(</span>
                        <div class="content">)" + msg.substr(msg.find(":") + 1) + R"(</div>
                    </div>
                )";
            }
        }

        response += R"(
                </div>
                <div class="footer">
                    <p>Powered by Your Chat Server</p>
                </div>
            </body>
            </html>
        )";

        res.set_content(response, "text/html");
    });

    // HTTP 서버 스레드 실행
    std::thread http_thread([&http_server]() {
        http_server.listen("0.0.0.0", 8080);
    });

    // TLS 클라이언트 처리
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_size = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_size);
        if (client_socket == -1) {
            std::cerr << "Failed to accept client.\n";
            continue;
        }

        // SSL 객체 생성 및 클라이언트와 연결
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        std::cout << "New client connected.\n";
        std::thread(handle_client, ssl).detach();
    }

    http_thread.join();
    close(server_socket);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
