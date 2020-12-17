<?php
// 类库名称：auth权限
// +----------------------------------------------------------------------
// | PHP version 5.6+
// +----------------------------------------------------------------------
// | Copyright (c) 2012-2014 http://www.myzy.com.cn, All rights reserved.
// +----------------------------------------------------------------------
// | Author: 阶级娃儿 <262877348@qq.com> 群：304104682
// +----------------------------------------------------------------------

namespace think;

use think\facade\Db;
use think\facade\Config;
use think\facade\Session;
use think\facade\Request;

class Auth
{
    /**
     * @var object 对象实例
     */
    protected static $instance;

    /**
     * @var array 配置信息
     */
    protected $config = [
        // 权限开关
        'auth_on'           => true,
        // 认证方式：1为实时认证；每次验证，都重新读取数据库内的权限数据，如果对权限验证非常敏感的，建议使用实时验证;2为登录认证 (即登录成功后，就把该用户用户的权限规则获取并保存到 session，之后就根据 session 值做权限验证判断)
        'auth_type'         => 1,
        // 角色用户组数据表名
        'auth_group'        => 'auth_group',
        // 用户-角色用户组关系表
        'auth_group_access' => 'auth_group_access',
        // 权限规则表
        'auth_rule'         => 'auth_rule',
        // 用户信息表
        'auth_user'         => 'member',
    ];

    /**
     * 构造函数
     * @access protected
     */
    public function __construct()
    {
        // 判断是否有设置配置项.此配置项为数组，做一个兼容
        if (Config::has('auth')) {
            // 合并,覆盖配置
            $this->config = array_merge($this->config, Config::get('auth'));
        }
    }

    /**
     * 初始化
     */
    public static function instance($options = [])
    {
        if (is_null(self::$instance)) {
            self::$instance = new static($options);
        }
        return self::$instance;
    }

    /**
     * [check 检查权限]
     * @param  string|array $name     [需要验证的规则列表,支持逗号分隔的权限规则或索引数组]
     * @param  int          $uuid      [认证用户的id]
     * @param  int          $type     [认证类型]
     * @param  string       $mode     [执行check的模式]
     * @param  boolean      $method   [验证请求方式]
     * @param  string       $relation [如果为 'or' 表示满足任一条规则即通过验证;如果为 'and'则表示需满足所有规则才能通过验证]
     * @return bool                   [通过验证返回true,失败返回false]
     */
    public function check($name = '', $uuid = '', $type = 1, $mode = 'url', $method = false, $relation = 'or')
    {
        if (empty($name) || empty($uuid)) {
            return '缺少参数！';
        } else {
            if ($this->config['auth_on'] === false) {
                return true;
            }

            // 获取用户需要验证的所有有效规则列表
            $authList = $this->getAuthList($uuid, $type);

            if (is_string($name)) {
                $name = strtolower($name);
                if (strpos($name, ',') !== false) {
                    $name = explode(',', $name);
                } else {
                    $name = [$name];
                }
            }

            //保存验证通过的规则名
            $list = [];

            if ('url' == $mode) {
                $REQUEST = unserialize(strtolower(serialize(Request::param())));
            }

            foreach ( $authList as $auth ) {
                $query = preg_replace('/^.+\?/U','',$auth);
                if ($mode=='url' && $query!=$auth ) {
                    //解析规则中的param
                    parse_str($query,$param);

                    $intersect = array_intersect_assoc($REQUEST,$param);
                    $auth = preg_replace('/\?.*$/U','',$auth);

                    //如果节点相符且url参数满足
                    if ( in_array($auth,$name) && $intersect==$param ) {
                        $list[] = $auth ;
                    }
                }else if (in_array($auth , $name)){
                     $list[] = $auth ;
                }
            }

            if ($relation == 'or' and !empty($list)) {
                return true;
            }

            $diff = array_diff($name, $list);
            if ($relation == 'and' and empty($diff)) {
                return true;
            }

            return false;
        }
    }

    /**
     * [getGroups 根据用户id获取用户组,返回值为数组]
     * @param  int  $uuid            [用户id]
     * @param  boolean $is_group    [用户所属的用户组]
     * @return bool                 [description]
     */
    public function getGroups($uuid, $is_group = false)
    {
        // 保存用户所属用户组设置的所有权限规则 id
        static $ids_arr = [];

        $auth_group_access = 'think_' . $this->config['auth_group_access'];
        $auth_group        = 'think_' . $this->config['auth_group'];

        // 执行查询
        $user_groups = Db::view($auth_group_access, 'member_id,group_id')
            ->view($auth_group, 'name,rules', "{$auth_group_access}.group_id={$auth_group}.id", 'LEFT')
            ->where("{$auth_group_access}.member_id='{$uuid}' and {$auth_group}.status='1'")
            ->select()
            ->toArray();

        if ($is_group) {
            return $user_groups;
        } else {
            foreach ($user_groups as $g) {
                $ids_arr = array_merge($ids_arr, explode(',', trim($g['rules'], ',')));
            }

            array_values($ids_arr);
            sort($ids_arr);

            $ids_arr = array_keys(array_flip($ids_arr));
            return $ids_arr;
        }
    }

    /**
     * [getAuthList 获得权限列表]
     * @param  int      $uuid   [用户id]
     * @param  int      $type  [认证类型]
     * @param  string   $field [字典显示]
     * @return array           [权限列表]
     */
    public function getAuthList($uuid, $type, $field = '', $sort = 'sort')
    {
        // 保存用户验证通过的权限列表
        static $_authList = [];

        $t = implode(',', (array) $type);

        if (isset($_authList[$uuid . $t])) {
            return $_authList[$uuid . $t];
        }

        // 判断权限验证方式
        if ($this->config['auth_type'] === 2 && Session::has('_auth_list_' . $uuid . $t)) {
            return Session::get('_auth_list_' . $uuid . $t);
        }

        //获取完整的表名
        $table_name = 'think_' . $this->config['auth_rule'];

        if (is_administrator($uuid)) {
            //return 11111;
            // 执行查询
            $rules = Db::table($table_name)->where(['status'=>1])->withoutField($field)->order($sort)->select()->toArray();
        } else {
            //return 22222;
            // 获取用户所属用户组
            $groups_ids = $this->getGroups($uuid);

            // 组成获取所有权限详细信息的数组条件
            $map = [
                ['id', 'in', $groups_ids],
                ['type', '=', $type],
                ['status', '=', 1]
            ];

            // 获取用户组所有权限规则
            $rules = Db::table($auth_rule)->where($map)->withoutField($field)->order($sort)->select()->toArray();
        }
        //return $rules;
        // 循环规则，判断结果
        foreach ($rules as $key => $rule) {
            // 判断是否有附加规则
            if (!empty($rule['condition'])) {
                $user = $static->getUserInfo($uuid);
                $command = preg_replace('/\{(\w*?)\}/', '$user[\'\\1\']', htmlspecialchars_decode($rule['condition']));

                @(eval('$condition=(' . $command . ');'));
                if ($condition) {
                    $rules[$key]['name'] = $rule['name'];
                    $method_type[] = $rule['type'];
                }
            } else {
                // 组成规则数组
                $rules[$key]['name'] = strtolower($rule['name']);
            }
        }

        if ($this->config['auth_type'] === 2) {
            // 规则列表结果保存到session
            Session::set('_auth_list_' . $uuid . $t, $rules);
        }

        return $rules;
    }

    /**
     * [getUserInfo 获得用户资料,根据自己的情况读取数据库]
     * @param  int $uuid     [用户ID]
     * @return array        [用户资料]
     */
    protected function getUserInfo($uuid)
    {
        static $userinfo = [];
        $user = Db::name($this->config['auth_user']);

        // 获取用户表主键
        $_pk = is_string($user->getPk()) ? $user->getPk() : 'uid';

        if (!isset($userinfo[$uuid])) {
            $userinfo[$uuid] = $user->where($_pk, $uuid)->find();
        }
        return $userinfo[$uuid];
    }
}