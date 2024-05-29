#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <relic.h>
#include <vector>
#include <algorithm>
#include <random>
#include <chrono>
#include "utils.hpp"

#include <thread>
#include <mutex>

using namespace std;
using namespace chrono;

std::mutex mtx;

void Receiver_set_registration_1(std::vector<bn_t> &Y, std::vector<g2_t> &K, bn_t rho, int start, int end)
{
    for (int i = start; i < end; ++i)
    {
        int dlen = Hash_F(Y[i], K[i]);
        g2_null(K[i]);
        g2_new(K[i]);
        g2_mul(K[i], K[i], rho);
    }
}

void Receiver_set_registration_2(std::vector<g2_t> &K, bn_t s, int start, int end)
{
    for (int i = start; i < end; ++i)
        g2_mul(K[i], K[i], s);
    
}

void Receiver_set_registration_3(std::vector<g2_t> &K, bn_t inv_rho, int start, int end)
{
    for (int i = start; i < end; ++i)
        g2_mul(K[i], K[i], inv_rho);

}

int main(int argc, char *argv[])
{
    std::vector<std::thread> threads;
    int rangeSize = n / numThreads;
    int remaining = n % numThreads;

    // Init for TCP
    int client_socket;
    struct sockaddr_in server_address;
    socklen_t addr_size;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    // Configure settings of the server address
    // Address family is Internet
    server_address.sin_family = AF_INET;

    // Set port number, using htons function
    server_address.sin_port = htons(1235);

    // Set IP address to localhost
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(server_address.sin_zero, '\0', sizeof(server_address.sin_zero));
    addr_size = sizeof(server_address);

    // Connect the socket to the server using the address
    if (connect(client_socket, reinterpret_cast<struct sockaddr *>(&server_address), addr_size) < 0)
    {
        std::cerr << "TCP/IP: Connection failed" << std::endl;
        return -1;
    }
    else
        std::cout << "TCP/IP: Connection established successfully" << std::endl;

    // Setup Phase
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

    // Receiver-set registration
    std::vector<bn_t> Y(n);
    std::vector<g2_t> K(n);

    for (int i = 0; i < n; ++i)
    {
        bn_null(Y[i]);
        bn_new(Y[i]);

        bn_rand_mod(Y[i], q);
    }

    bn_t rho;
    bn_null(rho);
    bn_new(rho);
    bn_rand_mod(rho, q);

    bn_t inv_rho;
    bn_null(inv_rho);
    bn_new(inv_rho);
    bn_mod_inv(inv_rho, rho, q);

    int start = 0;
    for (int i = 0; i < numThreads; ++i) {
        int end = start + rangeSize;
        if (i < remaining) {
            end += 1;
        }
        threads.emplace_back(Receiver_set_registration_1, std::ref(Y), std::ref(K), rho, start, end);
        start = end;
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    threads.clear();

    start = 0;
    for (int i = 0; i < numThreads; ++i) {
        int end = start + rangeSize;
        if (i < remaining) {
            end += 1;
        }
        threads.emplace_back(Receiver_set_registration_2, std::ref(K), s, start, end);
        start = end;
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    start = 0;
    for (int i = 0; i < numThreads; ++i) {
        int end = start + rangeSize;
        if (i < remaining) {
            end += 1;
        }
        threads.emplace_back(Receiver_set_registration_3, std::ref(K), inv_rho, start, end);
        start = end;
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    send(client_socket, "Hello", strlen("Hello"), 0);

    // Communication
    std::vector<uint8_t *> R(m);

    uint8_t PSI[2 * RLC_PC_BYTES + 1];
    memset(PSI, 0x00, 2 * RLC_PC_BYTES + 1);

    if (recv(client_socket, PSI, 2 * RLC_PC_BYTES + 1, 0) < 0)
        printf("Receive failed\n");

    for (int i = 0; i < m; i++)
    {
        R[i] = new uint8_t[SHA256_DIGEST_LENGTH];
        if (recv(client_socket, R[i], SHA256_DIGEST_LENGTH, 0) < 0)
            printf("Receive failed\n");
    }

    // Intersection Extraction
    g1_t psi;
    g1_null(psi);
    g1_new(psi);
    g1_read_bin(psi, PSI, 2 * RLC_PC_BYTES + 1);

    int intersection = 0;
    std::vector<uint8_t *> L(n);

    std::sort(R.begin(), R.end(), compareArrays);

    for (int i = 0; i < n; i++)
    {
        gt_t e;
        gt_null(e);
        gt_new(e);

        pc_map(e, psi, K[i]);

        uint8_t *temp;
        int dlen = Hash_H_hat(Y[i], e, temp);

        if (binarySearch(R, temp))
            intersection++;

        free(temp);
        gt_free(e);
    }

    for (int i = 0; i < n; ++i)
    {
        g2_free(K[i]);
        bn_free(Y[i]);
    }
    for (int i = 0; i < m; i++)
        delete[] R[i];

    g1_free(g1);
    g2_free(g2);
    bn_free(q);
    bn_free(s);
    g1_free(Gamma);
    bn_free(rho);
    bn_free(inv_rho);
    g1_free(psi);

    core_clean();
    //     sleep(50);
    // }

    return 0;
}