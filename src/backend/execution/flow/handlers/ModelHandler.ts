import { createLogger } from '@/utils/logger';
import { 
  ModelCallInput, 
  ModelCallResult, 
  ToolCallProcessingInput, 
  ToolCallProcessingResult 
} from '../types/modelHandler';
import { Result, ExecutionError } from '../errors';
import { createModelError, createToolError } from '../errorFactory';
import OpenAI from 'openai';
import { modelService } from '@/backend/services/model';
import { mcpService } from '@/backend/services/mcp';

const log = createLogger('backend/flow/execution/handlers/ModelHandler');

export class ModelHandler {
  /**
   * Call model with tool support - pure function that doesn't modify inputs
   */
  static async callModel(input: ModelCallInput): Promise<Result<ModelCallResult>> {
    const { modelId, prompt, messages, tools, iteration, maxIterations, nodeName } = input;
    
    // Fetch model information for display name
    let modelDisplayName = '';
    let modelTechnicalName = '';
    const nodeDisplayName = nodeName;
    try {
      const model = await modelService.getModel(modelId);
      if (model) {
        modelDisplayName = model.displayName || model.name;
        modelTechnicalName = model.name;
      }
    } catch (error) {
      log.warn(`Failed to fetch model information for prefix: ${error instanceof Error ? error.message : String(error)}`);
    }
    
    log.info(`callModel - Iteration ${iteration}/${maxIterations}`, {
      modelId,
      messagesCount: messages.length,
      toolsCount: tools?.length || 0
    });
    
    // Add verbose logging of the entire input
    log.verbose('callModel input', JSON.stringify(input));
    
    // Check iteration limit
    if (maxIterations > 0 && iteration > maxIterations) {
      const result: Result<ModelCallResult> = {
        success: true,
        value: {
          content: "Maximum tool call iterations reached. Some tool calls may not have been processed.",
          messages: [...messages]
        }
      };
      
      // Add verbose logging of the result
      log.verbose('callModel max iterations reached result', JSON.stringify(result));
      
      return result;
    }
    
    // Call the model API
    const response = await this.generateCompletion(modelId, prompt, messages, tools);
    
    if (!response.success) {
      // Add verbose logging of the error response
      log.verbose('callModel error response', JSON.stringify(response));
      
      // Ensure we're returning the complete error response with all details
      return {
        success: false,
        error: response.error
      };
    }
    
    const modelResponse = response.value;
    const content = modelResponse.content || '';
    const newMessages = [...messages];
    
    // Check for tool calls
    const hasToolCalls = this.hasToolCalls(modelResponse);
    
    if (hasToolCalls && tools && tools.length > 0) {
      // Process tool calls
      const toolCallsResult = await this.processToolCalls({
        toolCalls: modelResponse.fullResponse?.choices?.[0]?.message?.tool_calls || []
      });
      
      if (!toolCallsResult.success) {
        // Ensure we're returning the complete error response with all details
        log.verbose('Tool calls processing failed', JSON.stringify(toolCallsResult));
        return {
          success: false,
          error: toolCallsResult.error
        };
      }
      
      // Format content with model prefix and node name
      const prefixedContent = modelDisplayName 
        ? `## ${nodeDisplayName} - ${modelDisplayName} (${modelTechnicalName}) says:\n\n${content}`
        : content;

      // Add assistant message with tool calls
      const assistantMessage: OpenAI.ChatCompletionMessageParam = {
        role: 'assistant',
        content: prefixedContent,
        tool_calls: modelResponse.fullResponse?.choices?.[0]?.message?.tool_calls
      };
      newMessages.push(assistantMessage);
      
      // Add tool call messages
      const { toolCallMessages, processedToolCalls } = toolCallsResult.value;
      toolCallMessages.forEach(message => newMessages.push(message));
      
      // Recursively call the model with updated messages
      return this.callModel({
        modelId,
        prompt,
        messages: newMessages,
        tools,
        iteration: iteration + 1,
        maxIterations,
        nodeName
      });
    } else {
      // No tool calls, check for empty content with stop reason
      let messageContent = content;
      
      // If content is empty and there's a stop reason, provide a helpful message
      if (content === '' && modelResponse.fullResponse?.choices?.[0]?.finish_reason === 'stop') {
        messageContent = "I decided to stop processing your request without further explanation by setting a stop_reason.";
        log.info('Empty content with stop reason detected, using fallback message');
      }
      
      // Format content with model prefix and node name
      const prefixedContent = modelDisplayName 
        ? `## ${nodeDisplayName} - ${modelDisplayName} (${modelTechnicalName}) says:\n\n${messageContent}`
        : messageContent;

      // Add the assistant message
      const assistantMessage: OpenAI.ChatCompletionMessageParam = {
        role: 'assistant',
        content: prefixedContent
      };
      newMessages.push(assistantMessage);
      
      // Map tool calls to the correct format if they exist
      const toolCalls = modelResponse.fullResponse?.choices?.[0]?.message?.tool_calls?.map(toolCall => {
        try {
          return {
            name: toolCall.function.name,
            args: JSON.parse(toolCall.function.arguments),
            id: toolCall.id,
            result: '' // Empty result since these haven't been processed
          };
        } catch (e) {
          return {
            name: toolCall.function.name,
            args: {},
            id: toolCall.id,
            result: ''
          };
        }
      });
      
      // For the result, use the prefixed content
      // Return the final result
      const result: Result<ModelCallResult> = {
        success: true,
        value: {
          content: typeof assistantMessage.content === 'string' ? assistantMessage.content : messageContent, // Use the prefixed content for the result, ensuring it's a string
          messages: newMessages,
          fullResponse: modelResponse.fullResponse,
          toolCalls
        }
      };
      
      // Add verbose logging of the final result
      log.verbose('callModel final result', JSON.stringify(result));
      
      return result;
    }
  }
  
  /**
   * Generate completion using model service - pure function
   */
  /**
   * Generate completion using Anthropic API - pure function
   * This method handles the specific requirements of the Anthropic API
   */
  private static async generateAnthropicCompletion(
    model: any,
    apiKey: string,
    prompt: string,
    messages: OpenAI.ChatCompletionMessageParam[],
    temperature: number,
    tools?: OpenAI.ChatCompletionTool[]
  ): Promise<Result<ModelCallResult>> {
    log.debug('Using Anthropic-specific API call');
    
    try {
      // Validate API key
      if (!apiKey) {
        log.error('No API key provided for Anthropic API call');
        return {
          success: false,
          error: createModelError(
            'api_key_error',
            'No API key provided for Anthropic API call',
            model.id
          )
        };
      }
      
      // Log API key format (without revealing the actual key)
      log.debug('Anthropic API key format check:', {
        keyLength: apiKey.length,
        startsWithPrefix: apiKey.startsWith('sk-'),
        isAnthropicFormat: apiKey.startsWith('sk-ant')
      });
      
      // Ensure baseUrl ends with /v1 but avoid duplicate /v1/v1
      let baseUrl = model.baseUrl;
      if (!baseUrl.endsWith('/v1') && !baseUrl.endsWith('/v1/')) {
        baseUrl = baseUrl.endsWith('/') ? `${baseUrl}v1` : `${baseUrl}/v1`;
      }
      
      // Use the messages endpoint for Anthropic
      const messagesUrl = baseUrl.endsWith('/') ? `${baseUrl}messages` : `${baseUrl}/messages`;
      
      log.debug(`Making Anthropic API request to: ${messagesUrl}`);
      
      // Convert OpenAI messages format to Anthropic format
      // For simplicity, we'll just use the last user message
      // In a full implementation, you'd want to properly convert the entire conversation
      const userMessages = messages.filter(msg => msg.role === 'user');
      const lastUserMessage = userMessages[userMessages.length - 1];
      
      // Prepare the request body
      const requestBody = {
        model: model.name,
        messages: [
          {
            role: 'user',
            content: lastUserMessage?.content || prompt
          }
        ],
        temperature: temperature,
        max_tokens: 1024
      };
      
      // Prepare headers for Anthropic API
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01'
      };
      
      // Always add the API key as x-api-key header (Anthropic's expected format)
      headers['x-api-key'] = apiKey;
      
      // Log the headers we're using (without the actual API key value)
      log.debug('Using Anthropic API headers:', {
        contentType: headers['Content-Type'],
        hasApiKey: true,
        anthropicVersion: headers['anthropic-version']
      });
      
      // Make the API request with the prepared headers
      const response = await fetch(messagesUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody)
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        log.error(`Anthropic API error: ${response.status} ${response.statusText}`, { 
          errorText,
          requestUrl: messagesUrl,
          hasApiKey: !!apiKey,
          apiKeyLength: apiKey ? apiKey.length : 0,
          modelName: model.name
        });
        
        // Try to parse the error response for more details
        let parsedError = null;
        try {
          parsedError = JSON.parse(errorText);
          log.debug('Parsed Anthropic error response:', parsedError);
        } catch (e) {
          log.debug('Could not parse Anthropic error response as JSON');
        }
        
        return {
          success: false,
          error: createModelError(
            'api_error',
            `Anthropic API error: ${response.status} ${response.statusText}`,
            model.id,
            undefined,
            {
              status: response.status,
              type: 'anthropic_error',
              details: errorText,
              parsedError
            }
          )
        };
      }
      
      const data = await response.json();
      log.debug('Anthropic API response:', data);
      
      // Create a simplified response and use type assertion to avoid TypeScript errors
      // We don't need to fully match the OpenAI type, just provide what our code uses
      const openAICompatibleResponse = {
        id: data.id || `anthropic-${Date.now()}`,
        object: 'chat.completion',
        created: Date.now(),
        model: model.name,
        choices: [
          {
            index: 0,
            message: {
              role: 'assistant',
              content: data.content?.[0]?.text || ''
            },
            finish_reason: "stop" as const,
            logprobs: null
          }
        ]
      } as unknown as OpenAI.ChatCompletion;
      
      // Return the result in the expected format
      return {
        success: true,
        value: {
          content: data.content?.[0]?.text || '',
          messages: [...messages],
          fullResponse: openAICompatibleResponse
        }
      };
    } catch (error) {
      log.error(`Error in Anthropic API call: ${error instanceof Error ? error.message : String(error)}`);
      
      return {
        success: false,
        error: createModelError(
          'unknown_error',
          error instanceof Error ? error.message : String(error),
          model.id
        )
      };
    }
  }

  /**
   * Generate completion using model service - pure function
   */
  private static async generateCompletion(
    modelId: string,
    prompt: string,
    messages: OpenAI.ChatCompletionMessageParam[],
    tools?: OpenAI.ChatCompletionTool[]
  ): Promise<Result<ModelCallResult>> {
    // Add verbose logging of the input parameters
    log.verbose('generateCompletion input', JSON.stringify({
      modelId,
      prompt,
      messages,
      tools
    }));
    try {
      // Get the model
      const model = await modelService.getModel(modelId);
      if (!model) {
        return {
          success: false,
          error: createModelError(
            'model_not_found',
            `Model not found: ${modelId}`,
            modelId
          )
        };
      }

      // Extract model settings
      const temperature = model.temperature ? parseFloat(model.temperature) : 0.0;

      // Resolve and decrypt the API key
      const decryptedApiKey = await modelService.resolveAndDecryptApiKey(model.encryptedApiKey);
      if (!decryptedApiKey) {
        return {
          success: false,
          error: createModelError(
            'api_key_error',
            'Failed to resolve or decrypt API key',
            modelId
          )
        };
      }
      
      // Check if this is an Anthropic model
      if (model.provider === 'anthropic') {
        log.debug('Detected Anthropic model, using Anthropic-specific API call');
        return this.generateAnthropicCompletion(
          model,
          decryptedApiKey,
          prompt,
          messages,
          temperature,
          tools
        );
      }
      
      log.verbose(`decrypted api key ${decryptedApiKey}`)
      log.verbose(` baseurl ${model.baseUrl}`)
      // Initialize the OpenAI client
      const openai = new OpenAI({
        apiKey: decryptedApiKey,
        baseURL: model.baseUrl
      });
      
      // Create the request parameters
      const requestParams: OpenAI.Chat.ChatCompletionCreateParams = {
        model: model.name,
        messages: messages,
        temperature
      };
      
      // Add tools if available
      if (tools && tools.length > 0) {
        requestParams.tools = tools;
      } 
      

      log.verbose(`calling chatcompletion now with MODEL ${ JSON.stringify(requestParams.model)}`)
      log.verbose(`calling chatcompletion now with TEMP ${ JSON.stringify(requestParams.temperature)}`)
      log.verbose(`calling chatcompletion now with MESSAGES ${ JSON.stringify(requestParams.messages)}`)
      log.verbose(`calling chatcompletion now with TOOLS ${ JSON.stringify(requestParams.tools)}`)
      // Make the API request using the OpenAI client
      const chatCompletion = await openai.chat.completions.create(requestParams);
      log.verbose(`chatcompletion returned`)
      log.verbose(`chatcompletion returned ${ JSON.stringify(chatCompletion)}`)

      // Create a standardized response with OpenAI-compatible structure
      const result: Result<ModelCallResult> = {
        success: true,
        value: {
          content: chatCompletion.choices[0]?.message?.content || '',
          messages: [...messages],
          fullResponse: chatCompletion
        }
      };
      
      // Add verbose logging of the successful result
      log.verbose('generateCompletion success result', JSON.stringify(result));
      
      return result;
    } catch (error) {
      log.debug(`chatcompletion raised exception ${JSON.stringify(error)}`)
      // Handle API errors
      if (error instanceof OpenAI.APIError) {
        const errorResult: Result<ModelCallResult> = {
          success: false,
          error: createModelError(
            'api_error',
            error.message,
            modelId,
            undefined,
            {
              status: error.status,
              type: error.type,
              code: error.code,
              param: error.param
            }
          )
        };
        
        // Add verbose logging of the API error
        log.verbose('generateCompletion API error', JSON.stringify(errorResult));
        
        return errorResult;
      }
      
      // Handle other errors
      const errorResult: Result<ModelCallResult> = {
        success: false,
        error: createModelError(
          'unknown_error',
          error instanceof Error ? error.message : String(error),
          modelId
        )
      };
      
      // Add verbose logging of the unknown error
      log.verbose('generateCompletion unknown error', JSON.stringify(errorResult));
      
      return errorResult;
    }
  }
  
  /**
   * Process tool calls - pure function
   */
  private static async processToolCalls(
    input: ToolCallProcessingInput
  ): Promise<Result<ToolCallProcessingResult>> {
    const { toolCalls } = input;
    
    // Add verbose logging of the input
    log.verbose('processToolCalls input', JSON.stringify(input));
    
    if (!toolCalls || toolCalls.length === 0) {
      const emptyResult: Result<ToolCallProcessingResult> = {
        success: true,
        value: {
          toolCallMessages: [],
          processedToolCalls: []
        }
      };
      
      // Add verbose logging of the empty result
      log.verbose('processToolCalls empty result', JSON.stringify(emptyResult));
      
      return emptyResult;
    }
    
    try {
      // Array to collect new messages with tool results
      const toolCallMessages: OpenAI.ChatCompletionMessageParam[] = [];
      const processedToolCalls: Array<{
        name: string;
        args: Record<string, unknown>;
        id: string;
        result: string;
      }> = [];
      
      // Process each tool call
      for (const toolCall of toolCalls) {
        const { id, function: { name, arguments: argsString } } = toolCall;
        
        try {
          // Parse the arguments
          const args = JSON.parse(argsString);
          
          // Extract server and tool names from the formatted name
          // Format is "_-_-_serverName_-_-_toolName"
          const parts = name.split('_-_-_');
          if (parts.length !== 3) {
            throw new Error(`Invalid tool name format: ${name}`);
          }
          
          const serverName = parts[1];
          const toolName = parts[2];
          
          // Call the tool via MCP service
          const result = await mcpService.callTool(
            serverName,
            toolName,
            args
          );
          
          // Format the result
          const resultContent = result.success
            ? JSON.stringify(result.data)
            : `Error: ${result.error}`;
          
          // Add tool result message
          toolCallMessages.push({
            role: "tool",
            tool_call_id: id,
            content: resultContent
          });
          
          // Add to processed tool calls
          processedToolCalls.push({
            name,
            args,
            id,
            result: resultContent
          });
        } catch (error) {
          // Add error message for this specific tool call
          toolCallMessages.push({
            role: "tool",
            tool_call_id: id,
            content: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
          });
          
          // Add to processed tool calls with error
          processedToolCalls.push({
            name,
            args: {},
            id,
            result: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
          });
        }
      }
      
      const result: Result<ToolCallProcessingResult> = {
        success: true,
        value: {
          toolCallMessages,
          processedToolCalls
        }
      };
      
      // Add verbose logging of the successful result
      log.verbose('processToolCalls success result', JSON.stringify(result));
      
      return result;
    } catch (error) {
      const errorResult: Result<ToolCallProcessingResult> = {
        success: false,
        error: createToolError(
          'tool_processing_failed',
          error instanceof Error ? error.message : String(error),
          'unknown'
        )
      };
      
      // Add verbose logging of the error result
      log.verbose('processToolCalls error result', JSON.stringify(errorResult));
      
      return errorResult;
    }
  }
  
  /**
   * Check if response has tool calls - pure function
   */
  private static hasToolCalls(response: ModelCallResult): boolean {
    return !!(
      response.fullResponse?.choices?.[0]?.message?.tool_calls &&
      response.fullResponse.choices[0].message.tool_calls.length > 0
    );
  }
}
