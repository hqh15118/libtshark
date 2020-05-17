package com.tonggong.libtshark.pre_processor3.dumpcap;


import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-03-16 - 14:10
 */
public class DBConnectionTask implements Runnable{

    private Connection dbConnection;
    private LinkedBlockingQueue<DBOperationWrapper> sqlTaskQueue;
    private volatile boolean running = true;
    private LRUMap<String, PreparedStatement> sql2Preparement;
    private DBOperationWrapper dbOperationWrapper;

    public DBConnectionTask(int size){
        sqlTaskQueue = new LinkedBlockingQueue<>(size);
        sql2Preparement = new LRUMap<>(4, 0.75F);
    }

    public boolean offerTask(DBOperationWrapper sql){
        return sqlTaskQueue.offer(sql);
    }

    public boolean offerTask(DBOperationWrapper sql, int timeout, TimeUnit timeUnit) throws InterruptedException {
        return sqlTaskQueue.offer(sql,timeout,timeUnit);
    }

    public void putTask(DBOperationWrapper sql) throws InterruptedException {
        sqlTaskQueue.put(sql);
    }

    @Override
    public void run() {
        for (;running;){
            try {
                for (;running;){
                    dbOperationWrapper = sqlTaskQueue.poll(1000,TimeUnit.MILLISECONDS);
                    if (dbOperationWrapper != null){
                        PreparedStatement preparedStatement = sql2Preparement.
                                computeIfAbsent(dbOperationWrapper.sql, sql -> {
                                    PreparedStatement tmp = null;
                                    try {
                                        tmp = dbConnection.prepareStatement(sql);
                                        dbOperationWrapper.prepareStatement(tmp);
                                    } catch (SQLException e) {
                                        dbOperationWrapper.dbOperationCallback.fail(e,dbOperationWrapper);
                                    }
                                    return tmp;
                                });
                        if (preparedStatement != null){
                                dbConnection.setAutoCommit(false);
                                preparedStatement.executeBatch();
                                dbConnection.commit();
                                dbOperationWrapper.dbOperationCallback.success(dbOperationWrapper);
                        }
                   }
                }
            } catch (InterruptedException | SQLException e) {
                if (e instanceof InterruptedException){
                    running = false;
                }
                dbOperationWrapper.dbOperationCallback.fail(e,dbOperationWrapper);
                try {
                    dbConnection.rollback();
                } catch (SQLException e1) {
                    e1.printStackTrace();
                }
            }

        }
    }

    public static class DBOperationWrapper<T>{
        public String sql;
        public T data;
        public DBOperationCallback dbOperationCallback;

        /**
         * overwrite this method to init prepareStatement
         * @param preparedStatement
         * @throws SQLException
         */
        public void prepareStatement(PreparedStatement preparedStatement) throws SQLException {

        }
    }

    public interface DBOperationCallback{
        void success(DBOperationWrapper dbOperationWrapper);
        void fail(Exception e, DBOperationWrapper dbOperationWrapper);
    }
}
