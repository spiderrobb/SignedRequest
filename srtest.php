<?php
// signed request test
require 'SignedRequest.php';

// original data
$original_data = 'data text';
?><h2>original data <?php echo $original_data; ?></h2><?php

$signed_request_min = SignedRequest::encode($original_data);
?><h2>min request <?php echo $signed_request_min; ?></h2><?php
?><h2>original data <?php echo SignedRequest::decode($signed_request_min); ?></h2><?php

$signed_request_method = SignedRequest::encode($original_data, 'method');
?><h2>request method <?php echo $signed_request_method; ?></h2><?php
?><h2>original data <?php echo SignedRequest::decode($signed_request_method, 'method'); ?></h2><?php

$signed_request_method_secret = SignedRequest::encode($original_data, 'method', 'secret');
?><h2>request method secret <?php echo $signed_request_method_secret; ?></h2><?php
?><h2>original data <?php echo SignedRequest::decode($signed_request_method_secret, 'method', 'secret'); ?></h2><?php

$signed_request_time = SignedRequest::encode($original_data, false, false, 3);
?><h2>request time <?php echo $signed_request_method_secret; ?></h2><?php
?><h2>original data <?php echo SignedRequest::decode($signed_request_time); ?></h2><?php
?>