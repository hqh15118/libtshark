package com.tonggong.libtshark.pre_processor3;

import com.alibaba.fastjson.JSON;
import com.zjucsc.common.util.CuratorUtil;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.framework.api.CuratorListener;
import org.apache.curator.framework.recipes.cache.*;
import org.apache.curator.retry.ExponentialBackoffRetry;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.Watcher;
import org.checkerframework.checker.units.qual.C;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ThreadFactory;

public class ZKMain {

    private static NodeCache nodeCache;
    public static void main(String[] args) throws Exception {
        final String server = "localhost:2181";
        CuratorUtil curatorUtil = new CuratorUtil();
        curatorUtil.getClient(server,"capture-main-dev");
        Scanner scanner = new Scanner(System.in);
        Map<Integer,String> options = new HashMap<Integer, String>(){
            {
                put(0,"create");
                put(1,"delete");
                put(2,"setData");
                put(3,"getData");
                put(4,"getChildList");
                put(5,"pathWatcher");
                put(6,"removeWatcher");
                put(7,"nodeWatcher");
            }
        };
        Map<Integer, CreateMode> createModes = new HashMap<Integer, CreateMode>(){
            {
                put(1,CreateMode.CONTAINER);
                put(2,CreateMode.EPHEMERAL);
                put(3,CreateMode.EPHEMERAL_SEQUENTIAL);
                put(4,CreateMode.PERSISTENT_SEQUENTIAL);
                put(5,CreateMode.PERSISTENT);
            }
        };
        for (;;){
            try {
                System.out.println(options);
                int option = Integer.parseInt(scanner.nextLine());
                Object res = null;
                if (!options.containsKey(option)) {
                    break;
                }
                System.out.println("input operation node name : ");
                String nodeName = scanner.nextLine();
                switch (option) {
                    case 0:
                        //client.create().forPath(nodeName,"value".getBytes());
                        System.out.println(createModes);
                        CreateMode createMode = createModes.get(Integer.parseInt(scanner.nextLine()));
                        System.out.println("input init data");
                        curatorUtil.createNode(createMode,nodeName,scanner.nextLine().getBytes());
                        break;
                    case 1:
                        curatorUtil.deleteNode(nodeName);
                        break;
                    case 2:
                        System.out.println("input node data str : ");
                        curatorUtil.setData(nodeName, scanner.nextLine());
                        break;
                    case 3:
                        res = curatorUtil.getData(nodeName);
                        break;
                    case 4:
                        res = curatorUtil.getAllChild(nodeName);
                        break;
                    case 5:
                        res = curatorUtil.addPathWatcher(new PathChildrenCacheListener() {
                            @Override
                            public void childEvent(CuratorFramework curatorFramework, PathChildrenCacheEvent pathChildrenCacheEvent) throws Exception {
                                System.out.println("path event : " + pathChildrenCacheEvent);
                            }
                        },nodeName,false);
                        break;
                    case 6:
                        res = curatorUtil.getClient().watches().removeAll().forPath(nodeName);
                        break;
                    case 7:
                        nodeCache = curatorUtil.addNodeWatcher(new NodeCacheListener() {
                            @Override
                            public void nodeChanged() throws Exception {
                                System.out.println("node change!" + JSON.toJSONString(nodeCache.getCurrentData().getStat()));
                            }
                        }, nodeName, true);
                        res = nodeCache;
                        break;
                    case 8:
                        res = curatorUtil.addTreeWatcher(new TreeCacheListener() {
                            @Override
                            public void childEvent(CuratorFramework curatorFramework, TreeCacheEvent treeCacheEvent) throws Exception {
                                System.out.println("tree event : " + treeCacheEvent);
                            }
                        },nodeName);
                }
                if (res != null) {
                    System.out.println("result : " + JSON.toJSONString(res) + " type : " + res.getClass());
                }
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    /**
     * once watch
     */
    private static Watcher watcher = new Watcher() {
        @Override
        public void process(WatchedEvent watchedEvent) {

        }
    };

    private static abstract class NodeCacheListenerImpl implements NodeCacheListener{
        private final CuratorFramework client;
        public NodeCacheListenerImpl(CuratorFramework client){
            this.client = client;
        }
        protected CuratorFramework getClient(){
            return client;
        }
    }

    /**
     * 监听数据节点本身的变化。对节点的监听需要配合回调函数来进行处理接收到监听事件之后的业务处理。
     * NodeCache 通过 NodeCacheListener 来完成后续处理。
     */
//    private static final NodeCacheListenerImpl nodeCacheListener = new NodeCacheListenerImpl() {
//        @Override
//        public void nodeChanged() throws Exception {
//
//        }
//    };



    private static final TreeCacheListener treeCacheListener = new TreeCacheListener() {
        @Override
        public void childEvent(CuratorFramework curatorFramework, TreeCacheEvent treeCacheEvent) throws Exception {

        }
    };


    /**
     * once watcher
     * @param curatorClient
     * @param watcher
     * @param path
     * @return
     * @throws Exception
     */
    public static byte[] registerWatcher(CuratorFramework curatorClient,Watcher watcher,String path) throws Exception {
        return curatorClient.getData().usingWatcher(watcher).forPath(path);
    }

    /**
     *  CuratorListener 监听，此监听主要针对 background 通知和错误通知。
     *  使用此监听器之后，调用inBackground 方法会异步获得监听，对于节点的创建或修改则不会触发监听事件。
     *  recv msg
     *  curatorClient.getData().inBackground().forPath("/glmapper/test");
     * // 更新节点数据
     * no msg
     * curatorClient.setData().forPath("/glmapper/test","newData".getBytes());
     */
    public void registerCuratorListener(CuratorFramework curatorClient, CuratorListener curatorListener){
        curatorClient.getCuratorListenable().addListener(curatorListener);
    }

    /**
     * TreeNode
     * TreeCache 使用一个内部类TreeNode来维护这个一个树结构。并将这个树结构与ZK节点进行了映射。
     * 所以TreeCache 可以监听当前节点下所有节点的事件。
     */
    public static TreeCache registerTreeNodeWatcher(CuratorFramework curatorClient,String path,TreeCacheListener treeCacheListener) throws Exception {
        TreeCache treeCache = new TreeCache(curatorClient,path);
        treeCache.getListenable().addListener(treeCacheListener);
        return treeCache.start();
    }

    /**
     * watcher
     */
    public static NodeCache registerPermanentWatcher(CuratorFramework curatorClient,String path,
                                                 NodeCacheListener nodeCacheListener,boolean initial) throws Exception {
        final NodeCache nodeCache = new NodeCache(curatorClient,path);
        //如果设置为true则在首次启动时就会缓存节点内容到Cache中。 nodeCache.start(true);
        //nodeCache.start();
        nodeCache.start(initial);
        nodeCache.getListenable().addListener(nodeCacheListener);
        return nodeCache;
    }

    /**
     * PathChildrenCache
     * PathChildrenCache 不会对二级子节点进行监听，只会对子节点进行监听。
     */
    public static PathChildrenCache registerPathChildrenCache(CuratorFramework curatorClient, String path,
                                                 PathChildrenCacheListener pathChildrenCacheListener,
                                                 boolean initial,
                                                 boolean compressed,
                                                 PathChildrenCache.StartMode startMode,
                                                 ThreadFactory threadFactory) throws Exception {
        PathChildrenCache pathChildrenCache = new PathChildrenCache(curatorClient,path,initial,compressed,threadFactory);
        pathChildrenCache.start(startMode);
        pathChildrenCache.getListenable().addListener(pathChildrenCacheListener);
        return pathChildrenCache;
    }

    //transaction
    /**
     * // 开启事务
     * CuratorTransaction curatorTransaction = curatorClient.inTransaction();
     * Collection<CuratorTransactionResult> commit =
     *   // 操作1
     * curatorTransaction.create().withMode(CreateMode.EPHEMERAL).forPath("/glmapper/transaction")
     *   .and()
     *   // 操作2
     *   .delete().forPath("/glmapper/test")
     *   .and()
     *   // 操作3
     *   .setData().forPath("/glmapper/transaction", "data".getBytes())
     *   .and()
     *   // 提交事务
     *   .commit();
     * Iterator<CuratorTransactionResult> iterator = commit.iterator();
     * while (iterator.hasNext()){
     *   CuratorTransactionResult next = iterator.next();
     *   System.out.println(next.getForPath());
     *   System.out.println(next.getResultPath());
     *   System.out.println(next.getType());
     * }
     *
     */

    /**
     * async
     */
    //public T inBackground(BackgroundCallback callback, Executor executor);
}
