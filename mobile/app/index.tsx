import { Text, View } from "react-native";
import "./global.css"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
export default function Index() {
  return (
    <View className="flex-1 justify-center">
      <>
        <Accordion type='single' collapsible>
          <AccordionItem value='item-1'>
            <AccordionTrigger>
              <Text className="">Is it accessible?</Text>
            </AccordionTrigger>
            <AccordionContent>
              <Text className="">Yes. It adheres to the WAI-ARIA design pattern.</Text>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </>
    </View>
  );
}
