#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>  // for open
#include <unistd.h> // for close
#include <vector>
#include <algorithm>
#include <random>

#include <chrono>
#include <thread>

#include <relic.h>
#include "utils.hpp"

using namespace std;
using namespace chrono;
void First_Round_1(std::vector<bn_t> &X, std::vector<gt_t> &CHI, bn_t q, g1_t Gamma, int start, int end)
{
    for (int i = start; i < end; ++i)
    {
        bn_null(X[i]);
        bn_new(X[i]);

        bn_rand_mod(X[i], q);

        g2_t temp;
        g2_null(temp);
        g2_new(temp);

        int dlen = Hash_F(X[i], temp);

        gt_null(CHI[i]);
        gt_new(CHI[i]);
        pc_map(CHI[i], Gamma, temp);

        g2_free(temp);
    }
}

void First_Round_2(std::vector<bn_t> &X, std::vector<gt_t> &CHI, const unsigned int *shuffle, std::vector<uint8_t *> &R, bn_t r, int start, int end)
{
    for (int i = start; i < end; ++i)
    {
        gt_t temp;
        gt_null(temp);
        gt_new(temp);

        gt_exp(temp, CHI[shuffle[i]], r);
        int dlen = Hash_H(temp, R[i]);

        gt_free(temp);
    }
}

int main(int argc, char *argv[])
{
    system_clock::time_point t_time_begin, t_time_end;
    nanoseconds Setup_time = std::chrono::nanoseconds(0);
    nanoseconds First_Round_time1 = std::chrono::nanoseconds(0);
    nanoseconds First_Round_time2 = std::chrono::nanoseconds(0);
    nanoseconds Communication_time = std::chrono::nanoseconds(0);
    nanoseconds Total_time = std::chrono::nanoseconds(0);

    std::cout << "Semi-Honest Model - Sender:" << std::endl;
    std::cout << "n = " << n << ", m = " << m << std::endl;

    std::vector<std::thread> threads;
    int rangeSize = m / numThreads;
    int remaining = m % numThreads;

    // Init for TCP
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        std::cerr << "TCP/IP: Error creating socket\n";
        return 1;
    }

    int reuse = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        std::cerr << "Error setting SO_REUSEADDR option" << std::endl;
        close(server_socket);
        return 1;
    }

    sockaddr_storage server_storage;
    socklen_t addr_size;

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(1234);

    memset(server_address.sin_zero, '\0', sizeof(server_address.sin_zero));

    if (bind(server_socket, reinterpret_cast<sockaddr *>(&server_address), sizeof(server_address)) < 0)
    {
        std::cerr << "TCP/IP: Binding failed\n";
        return 1;
    }

    if (listen(server_socket, 50) == 0)
        std::cout << "TCP/IP: listening\n";
    else
        std::cerr << "TCP/IP: Error\n";

    int client_socket;
    struct sockaddr_in clientAddress;
    socklen_t clientAddrSize = sizeof(clientAddress);
    client_socket = accept(server_socket, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddrSize);

    if (client_socket == -1)
    {
        std::cerr << "TCP/IP: Error accepting connection\n";
        close(server_socket);
        return 1;
    }

    // Setup Phase
    t_time_begin = system_clock::now();
    if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK)
    {
        printf("Relic initialization failed.\n");
        return 1;
    }

    g1_t g1;
    g1_null(g1);
    g1_new(g1);
    g1_get_gen(g1);

    g2_t g2;
    g2_null(g2);
    g2_new(g2);
    g2_get_gen(g2);

    bn_t q;
    bn_null(q);
    bn_new(q);
    pc_get_ord(q);

    bn_t s;
    bn_null(s);
    bn_new(s);
    bn_read_str(s, S, strlen(S), 16);

    g1_t Gamma;
    g1_null(Gamma);
    g1_new(Gamma);
    g1_mul(Gamma, g1, s);

    t_time_end = system_clock::now();
    Setup_time = duration_cast<nanoseconds>(t_time_end - t_time_begin);
    Total_time += Setup_time;

    // First_Round
    t_time_begin = system_clock::now();

    std::vector<bn_t> X(m);
    std::vector<gt_t> CHI(m);
    bn_t r;
    bn_null(r);
    bn_new(r);
    bn_rand_mod(r, q);

    g1_t psi;
    g1_null(psi);
    g1_new(psi);
    g1_mul(psi, g1, r);

    std::vector<uint8_t *> R(m);

    unsigned int *shuffle = RLC_ALLOCA(unsigned int, n);
    util_perm(shuffle, m);
    int start = 0;
    for (int i = 0; i < numThreads; ++i)
    {
        int end = start + rangeSize;
        if (i < remaining)
        {
            end += 1;
        }
        threads.emplace_back(First_Round_1, std::ref(X), std::ref(CHI), q, Gamma, start, end);
        start = end;
    }

    for (auto &th : threads)
    {
        if (th.joinable())
        {
            th.join();
        }
    }

    t_time_end = system_clock::now();
    First_Round_time1 = duration_cast<nanoseconds>(t_time_end - t_time_begin);
    Total_time += First_Round_time1;

    threads.clear();

    t_time_begin = system_clock::now();
    start = 0;
    for (int i = 0; i < numThreads; ++i)
    {
        int end = start + rangeSize;
        if (i < remaining)
        {
            end += 1;
        }
        threads.emplace_back(First_Round_2, std::ref(X), std::ref(CHI), std::ref(shuffle), std::ref(R), r, start, end);
        start = end;
    }

    for (auto &th : threads)
    {
        if (th.joinable())
        {
            th.join();
        }
    }

    t_time_end = system_clock::now();
    First_Round_time2 = duration_cast<nanoseconds>(t_time_end - t_time_begin);
    Total_time += First_Round_time2;

    uint8_t PSI[2 * RLC_PC_BYTES + 1];

    if (recv(client_socket, PSI, strlen("Hello"), 0) < 0)
    {
        printf("Receive failed\n");
    }
    else
        printf("Connection complete\n");

    t_time_begin = system_clock::now();
    memset(PSI, 0x00, 2 * RLC_PC_BYTES + 1);
    g1_write_bin(PSI, 2 * RLC_PC_BYTES + 1, psi, 0);

    if (send(client_socket, PSI, 2 * RLC_PC_BYTES + 1, 0) == -1)
        std::cerr << "TCP/IP: Send failed" << std::endl;

    for (int i = 0; i < m; i++)
    {
        if (send(client_socket, R[i], SHA256_DIGEST_LENGTH, 0) == -1)
            std::cerr << "TCP/IP: Send failed" << std::endl;
    }
    close(client_socket);

    t_time_end = system_clock::now();
    Communication_time = duration_cast<nanoseconds>(t_time_end - t_time_begin);
    Total_time += Communication_time;

    std::cout << "Setup Time = " << to_string(Setup_time.count()) << "(ns)" << std::endl;
    std::cout << "Communication Time = " << to_string(Communication_time.count()) << "(ns)" << std::endl;
    std::cout << "First Round Time 1 = " << to_string(First_Round_time1.count()) << "(ns)" << std::endl;
    std::cout << "First Round Time 2 = " << to_string(First_Round_time2.count()) << "(ns)" << std::endl;
    std::cout << "Total Time = " << to_string(Total_time.count()) << "(ns)" << std::endl
              << std::endl;

    for (int i = 0; i < m; ++i)
    {
        gt_free(CHI[i]);
        bn_free(X[i]);
    }

    g1_free(g1);
    g2_free(g2);
    bn_free(q);
    bn_free(s);
    g1_free(Gamma);
    bn_free(r);
    g1_free(psi);

    core_clean();

    return 0;
}