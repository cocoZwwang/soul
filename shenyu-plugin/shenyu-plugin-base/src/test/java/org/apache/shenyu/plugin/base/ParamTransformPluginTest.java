/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shenyu.plugin.base;

import org.apache.shenyu.common.constant.Constants;
import org.apache.shenyu.common.enums.PluginEnum;
import org.apache.shenyu.common.enums.RpcTypeEnum;
import org.apache.shenyu.plugin.api.SoulPluginChain;
import org.apache.shenyu.plugin.api.context.SoulContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

/**
 * TThe param transform plugin test.
 */
@RunWith(MockitoJUnitRunner.class)
public final class ParamTransformPluginTest {
    
    private SoulPluginChain chain;
    
    private ParamTransformPlugin paramTransformPlugin;
    
    /**
     * Sets up.
     */
    @Before
    public void setUp() {
        paramTransformPlugin = new ParamTransformPlugin();
        chain = mock(SoulPluginChain.class);
    }
    
    /**
     * Test get order.
     */
    @Test
    public void testGetOrder() {
        int result = paramTransformPlugin.getOrder();
        assertEquals(PluginEnum.PARAM_TRANSFORM.getCode(), result);
    }
    
    /**
     * Test named.
     */
    @Test
    public void testNamed() {
        String result = paramTransformPlugin.named();
        assertEquals(PluginEnum.PARAM_TRANSFORM.getName(), result);
    }
    
    /**
     * Test json body.
     */
    @Test
    public void testJsonBody() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("localhost").contentType(MediaType.APPLICATION_JSON).body("{}"));
        Mockito.when(chain.execute(exchange)).thenReturn(Mono.empty());
        SoulContext context = new SoulContext();
        context.setRpcType(RpcTypeEnum.DUBBO.getName());
        exchange.getAttributes().put(Constants.CONTEXT, context);
        Mono<Void> result = paramTransformPlugin.execute(exchange, chain);
        StepVerifier.create(result).expectSubscription().verifyComplete();
    }
    
    /**
     * Test format body.
     */
    @Test
    public void testFormatBody() {
        final ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("localhost").contentType(MediaType.APPLICATION_FORM_URLENCODED).body("test=test"));
        Mockito.when(chain.execute(exchange)).thenReturn(Mono.empty());
        SoulContext context = new SoulContext();
        context.setRpcType(RpcTypeEnum.DUBBO.getName());
        exchange.getAttributes().put(Constants.CONTEXT, context);
        Mono<Void> result = paramTransformPlugin.execute(exchange, chain);
        StepVerifier.create(result).expectSubscription().verifyComplete();
    }
    
    /**
     * Test no body.
     */
    @Test
    public void testNoBody() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("localhost"));
        Mockito.when(chain.execute(exchange)).thenReturn(Mono.empty());
        SoulContext context = new SoulContext();
        context.setRpcType(RpcTypeEnum.DUBBO.getName());
        exchange.getAttributes().put(Constants.CONTEXT, context);
        Mono<Void> result = paramTransformPlugin.execute(exchange, chain);
        StepVerifier.create(result).expectSubscription().verifyComplete();
    }
    
    /**
     * Test simple body.
     */
    @Test
    public void testSimpleBody() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("localhost").body("test"));
        Mockito.when(chain.execute(exchange)).thenReturn(Mono.empty());
        SoulContext context = new SoulContext();
        context.setRpcType(RpcTypeEnum.DUBBO.getName());
        exchange.getAttributes().put(Constants.CONTEXT, context);
        Mono<Void> result = paramTransformPlugin.execute(exchange, chain);
        StepVerifier.create(result).expectSubscription().verifyComplete();
    }
}
