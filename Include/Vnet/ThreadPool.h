/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNET_THREADPOOL_H_
#define _VNET_THREADPOOL_H_

#include <cstdint>
#include <thread>
#include <vector>
#include <queue>
#include <tuple>
#include <functional>
#include <condition_variable>
#include <mutex>
#include <exception>
#include <stdexcept>

namespace Vnet {

    /**
     * Represents a pool of threads used to execute jobs.
     */
    template <typename... Ts>
    class ThreadPool {

    private:
        bool m_active;
        std::int32_t m_threadCount;
        std::vector<std::thread> m_threads;
        std::queue<std::tuple<std::function<void(Ts...)>, std::tuple<Ts...>>> m_jobQueue;
        std::mutex m_mutex;
        std::condition_variable m_condition;

    public:

        /**
         * Constructs a new ThreadPool object.
         * 
         * @tparam Ts... Variadic template arguments representing the parameter types passed to the job function.
         * @param threadCount The number of threads in the thread pool.
         * @exception std::invalid_argument - The 'threadCount' parameter is less than or equal to zero.
         */
        ThreadPool(const std::int32_t threadCount);

        ThreadPool(const ThreadPool&) = delete;
        ThreadPool(ThreadPool&&) noexcept = delete;
        virtual ~ThreadPool(void);

        ThreadPool& operator= (const ThreadPool&) = delete;
        ThreadPool& operator= (ThreadPool&&) noexcept = delete;

    private:
        void ThreadProc(void);

    public:

        /**
         * Adds a job to the thread pool's job queue.
         * 
         * @tparam Ts... Variadic template arguments representing the parameter types passed to the job function.
         * @param fn The function to be executed.
         * @param args The arguments passed to the function.
         */
        void EnqueueJob(const std::function<void(Ts...)> fn, Ts... args);

        /**
         * Returns the number of threads in the thread pool.
         * 
         * @returns An integer.
         */
        std::int32_t GetThreadCount(void) const;

        /**
         * Returns the number of jobs currently in the job queue.
         * 
         * @returns An integer.
         */
        std::int32_t GetJobCount(void) const;

    };

    template <typename... Ts>
    inline ThreadPool<Ts...>::ThreadPool(const std::int32_t threadCount) {

        if (threadCount <= 0)
            throw std::invalid_argument("'threadCount': Cannot create a thread pool of zero or fewer threads.");

        this->m_active = true;
        this->m_threadCount = threadCount;
        this->m_threads = std::vector<std::thread>(threadCount);
        this->m_jobQueue = { };

        for (std::int32_t i = 0; i < this->m_threadCount; ++i)
            this->m_threads[i] = std::thread(&ThreadPool<Ts...>::ThreadProc, this);

    }

    template <typename... Ts>
    inline ThreadPool<Ts...>::~ThreadPool() { 

        this->m_active = false;
        this->m_condition.notify_all();

        for (std::int32_t i = 0; i < this->m_threadCount; ++i)
            this->m_threads[i].join();

        this->m_threads.clear();

    }

    template <typename... Ts>
    inline void ThreadPool<Ts...>::ThreadProc() {
        
        while (true) {

            std::tuple<std::function<void(Ts...)>, std::tuple<Ts...>> t;
            {

                std::unique_lock<std::mutex> lock(this->m_mutex);
                this->m_condition.wait(lock, [&] (void) -> bool {
                    return (!m_jobQueue.empty() || !m_active);
                });

                if (!this->m_active) return;

                t = this->m_jobQueue.front();
                this->m_jobQueue.pop();

            }

            std::apply(std::get<0>(t), std::get<1>(t));

        }

    }

    template <typename... Ts>
    inline void ThreadPool<Ts...>::EnqueueJob(const std::function<void(Ts...)> fn, Ts... args) {
        const std::lock_guard<std::mutex> guard(this->m_mutex);
        this->m_jobQueue.push({ fn, { args... } });
        this->m_condition.notify_one();
    }

    template <typename... Ts>
    inline std::int32_t ThreadPool<Ts...>::GetThreadCount() const {
        return this->m_threadCount;
    }

    template <typename... Ts>
    inline std::int32_t ThreadPool<Ts...>::GetJobCount() const {
        return this->m_jobQueue.size();
    }

}

#endif // _VNET_THREADPOOL_H_